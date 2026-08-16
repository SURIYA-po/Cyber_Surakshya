"""Response Agent LangGraph node.

Responsibilities (strict boundary):
  DOES:
    - Read DecisionResult from PlatformSharedState
    - Enforce the approval gate (decision approval + live analyst approvals)
    - Enforce the safety gate (ActionGuard: trust, protected targets, blast radius)
    - Resolve an executor from ExecutorRegistry and invoke it
    - Append one validated ResponseResult to state.response_results

  DOES NOT:
    - Read AnalysisResult, DetectionResult, or SecurityEvent.
      DecisionResult is its only input contract.
    - Re-evaluate policy or choose a different action than the one decided.
      The guard may deny or downgrade; it may never escalate.
    - Mutate DecisionResult. Decision lifecycle is a projection over
      response_results — see docs/response_agent.md.
    - Call an LLM. The AI lives in the decision engine; execution is
      deliberately deterministic.

This is the only node in the platform that can produce a real-world
side-effect, so every path through it is auditable: each ResponseResult
records the guard verdict, the engine trust tier, and every execution attempt.
"""
from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from adapters.response.base import (
    ExecutionReceipt,
    ExecutionRequest,
    ResponseExecutor,
    TransientExecutorError,
)
from adapters.response.registry import ExecutorRegistry, MissingExecutorError
from agents.response.approval import ApprovalStore
from agents.response.config import ResponsePolicyConfig
from agents.response.guard import ActionGuard, GuardDecision
from cyber_surakshya.platform.actions.action import Action
from cyber_surakshya.platform.actions.action_type import ActionType
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.schemas.decision_result import (
    ApprovalStatus,
    DecisionResult,
)
from cyber_surakshya.platform.schemas.response_result import (
    EngineTrustTier,
    ExecutionAttempt,
    GuardVerdict,
    ResponseResult,
    ResponseStatus,
)
from cyber_surakshya.platform.state import PlatformSharedState, PlatformStateModel
from memory.base import MemoryProvider
from memory.models import MemoryQuery, MemoryRecord

logger = logging.getLogger(__name__)

RESPONSE_COLLECTION = "responses"
_RECORD_TYPE = "response_result"


class ResponseAgent:
    """LangGraph node that authorises and executes a decided action.

    Injected dependencies (constructor):
      - ``executor_registry`` — routes actions to integrations.
      - ``guard``             — authorisation policy (defaults to fail-closed).
      - ``approval_store``    — live analyst approvals (optional).
      - ``memory_provider``   — audit trail and idempotency (optional).

    ResponseAgent never imports a concrete integration; all are injected at
    startup via app.py::ensure_runtime.
    """

    def __init__(
        self,
        executor_registry: ExecutorRegistry,
        *,
        guard: ActionGuard | None = None,
        approval_store: ApprovalStore | None = None,
        memory_provider: MemoryProvider | None = None,
        config: ResponsePolicyConfig | None = None,
        agent_name: str = "response_agent",
    ) -> None:
        self.executor_registry = executor_registry
        self.config            = config or (guard.config if guard else ResponsePolicyConfig())
        self.guard             = guard or ActionGuard(self.config)
        self.approval_store    = approval_store
        self.memory_provider   = memory_provider
        self.agent_name        = agent_name

    def __call__(self, state: PlatformSharedState) -> PlatformSharedState:
        """Execute one pending DecisionResult and return a state update."""
        state_model: PlatformStateModel | None = None
        try:
            state_model = PlatformStateModel.from_graph_state(state)
            decision    = self._next_decision_for_response(state_model)

            if decision is None:
                logger.info(
                    "response_agent_no_pending_decision",
                    extra={
                        "agent":          self.agent_name,
                        "correlation_id": state_model.correlation_id,
                        "trace_id":       state_model.trace_id,
                        "session_id":     state_model.session_id,
                    },
                )
                return self._metadata_update(
                    state_model,
                    status="skipped",
                    reason="no_pending_decision_results",
                )

            logger.info(
                "response_agent_started",
                extra={
                    "agent":           self.agent_name,
                    "decision_id":     decision.decision_id,
                    "action_type":     decision.action.action_type.value,
                    "decision_engine": decision.decision_engine,
                    "correlation_id":  state_model.correlation_id,
                    "trace_id":        state_model.trace_id,
                },
            )

            t0     = time.perf_counter()
            result = self._process(decision)
            result = result.model_copy(
                update={"response_duration_ms": round((time.perf_counter() - t0) * 1000.0, 3)}
            )

            self._store_memory(decision, result)

            logger.info(
                "response_agent_completed",
                extra={
                    "agent":         self.agent_name,
                    "response_id":   result.response_id,
                    "decision_id":   result.decision_id,
                    "status":        result.status.value,
                    "action_type":   result.action.action_type.value,
                    "guard_verdict": result.guard_verdict.value,
                    "guard_rule":    result.guard_rule,
                    "trust_tier":    result.engine_trust_tier.value,
                    "executor":      result.executor_name,
                    "duration_ms":   result.response_duration_ms,
                },
            )
            return self._success_update(state_model, result)

        except Exception as exc:
            logger.exception(
                "response_agent_failed",
                extra={
                    "agent":      self.agent_name,
                    "error_type": type(exc).__name__,
                },
            )
            return self._error_update(state_model, exc)

    # ── Pipeline ──────────────────────────────────────────────────────────────

    def _process(self, decision: DecisionResult) -> ResponseResult:
        """Run one decision through the approval, safety, and execution gates."""
        # 1. Rejection is terminal — never reaches the guard.
        human_ruling = self._resolve_human_ruling(decision)
        if human_ruling is False or decision.approval_status is ApprovalStatus.REJECTED:
            return self._build_result(
                decision,
                action=decision.action,
                status=ResponseStatus.NO_OP,
                guard_verdict=GuardVerdict.DENY,
                guard_rule="analyst_rejected",
                guard_reason=(
                    "An analyst rejected this decision. No action will be taken."
                ),
                tier=self.guard.trust_policy.tier_for(decision.decision_engine),
            )

        human_approved = human_ruling is True

        # 2. Decision-level approval gate.
        if decision.requires_approval and not human_approved:
            return self._awaiting_approval(
                decision,
                rule="decision_requires_approval",
                reason=(
                    f"Decision requires analyst approval (approval_status="
                    f"{decision.approval_status.value}). Execution deferred."
                ),
            )

        # 3. Idempotency, before the guard. A replay of an action that already
        #    happened must not consume blast-radius budget, and "we already did
        #    this" is a more accurate account than "you have done too much".
        idempotency_key = self._idempotency_key(decision, decision.action)
        duplicate = self._find_duplicate(idempotency_key)
        if duplicate is not None:
            return self._build_result(
                decision,
                action=decision.action,
                status=ResponseStatus.DEDUPLICATED,
                guard_verdict=GuardVerdict.ALLOW,
                guard_rule="idempotent_replay",
                guard_reason=(
                    f"An identical action was already executed within the "
                    f"{self.config.idempotency_window_seconds}s idempotency "
                    f"window (response {duplicate})."
                ),
                tier=self.guard.trust_policy.tier_for(decision.decision_engine),
                idempotency_key=idempotency_key,
                duplicate_of_response_id=duplicate,
            )

        # 4. Safety gate.
        guard_decision = self.guard.evaluate(decision, human_approved=human_approved)

        if guard_decision.verdict is GuardVerdict.DENY:
            return self._build_result(
                decision,
                action=guard_decision.action,
                status=ResponseStatus.BLOCKED_BY_GUARD,
                guard_verdict=GuardVerdict.DENY,
                guard_rule=guard_decision.rule,
                guard_reason=guard_decision.reason,
                tier=guard_decision.tier,
            )

        if guard_decision.verdict is GuardVerdict.REQUIRE_APPROVAL:
            return self._awaiting_approval(
                decision,
                rule=guard_decision.rule,
                reason=guard_decision.reason,
                tier=guard_decision.tier,
            )

        # 5. LOG_ONLY never reaches an executor — recording it is the action.
        if guard_decision.action.action_type is ActionType.LOG_ONLY:
            return self._build_result(
                decision,
                action=guard_decision.action,
                status=ResponseStatus.NO_OP,
                guard_verdict=guard_decision.verdict,
                guard_rule=guard_decision.rule,
                guard_reason=guard_decision.reason,
                tier=guard_decision.tier,
                idempotency_key=idempotency_key,
            )

        # 6. Execute.
        return self._execute(decision, guard_decision, idempotency_key)

    def _execute(
        self,
        decision: DecisionResult,
        guard_decision: GuardDecision,
        idempotency_key: str,
    ) -> ResponseResult:
        """Resolve an executor and invoke it with bounded retry."""
        action = guard_decision.action
        try:
            executor = self.executor_registry.resolve(
                action.action_type, action.target.target_type
            )
        except MissingExecutorError as exc:
            logger.error(
                "response_agent_no_executor",
                extra={
                    "agent":       self.agent_name,
                    "action_type": action.action_type.value,
                    "target_type": action.target.target_type,
                    "decision_id": decision.decision_id,
                },
            )
            return self._build_result(
                decision,
                action=action,
                status=ResponseStatus.FAILED,
                guard_verdict=guard_decision.verdict,
                guard_rule=guard_decision.rule,
                guard_reason=guard_decision.reason,
                tier=guard_decision.tier,
                idempotency_key=idempotency_key,
                attempts=[
                    ExecutionAttempt(
                        attempt_number=1,
                        succeeded=False,
                        duration_ms=0.0,
                        error_type=type(exc).__name__,
                        error_message=str(exc)[:1024],
                    )
                ],
            )

        request = ExecutionRequest(
            action=action,
            correlation_id=decision.correlation_id,
            trace_id=decision.trace_id,
            decision_id=decision.decision_id,
            idempotency_key=idempotency_key,
            dry_run=guard_decision.dry_run,
            timeout_seconds=self.config.execution_timeout_seconds,
        )

        attempts: list[ExecutionAttempt] = []
        receipt: ExecutionReceipt | None = None

        for attempt_number in range(1, self.config.max_retries + 2):
            started = time.perf_counter()
            try:
                receipt = executor.execute(request)
                attempts.append(
                    ExecutionAttempt(
                        attempt_number=attempt_number,
                        succeeded=True,
                        duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                    )
                )
                break
            except TransientExecutorError as exc:
                attempts.append(
                    ExecutionAttempt(
                        attempt_number=attempt_number,
                        succeeded=False,
                        duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                        error_type=type(exc).__name__,
                        error_message=str(exc)[:1024],
                    )
                )
                logger.warning(
                    "response_agent_transient_failure",
                    extra={
                        "agent":       self.agent_name,
                        "attempt":     attempt_number,
                        "action_type": action.action_type.value,
                        "error":       str(exc),
                    },
                )
            except Exception as exc:
                # Permanent failure. Retrying an action whose side-effect
                # status is unknown is more dangerous than failing.
                attempts.append(
                    ExecutionAttempt(
                        attempt_number=attempt_number,
                        succeeded=False,
                        duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                        error_type=type(exc).__name__,
                        error_message=str(exc)[:1024],
                    )
                )
                break

        succeeded = receipt is not None and receipt.succeeded
        if not succeeded:
            return self._build_result(
                decision,
                action=action,
                status=ResponseStatus.FAILED,
                guard_verdict=guard_decision.verdict,
                guard_rule=guard_decision.rule,
                guard_reason=guard_decision.reason,
                tier=guard_decision.tier,
                idempotency_key=idempotency_key,
                attempts=attempts,
                executor=executor,
            )

        if guard_decision.verdict is GuardVerdict.DOWNGRADE:
            status = ResponseStatus.DOWNGRADED
        elif guard_decision.dry_run:
            status = ResponseStatus.DRY_RUN
        else:
            status = ResponseStatus.EXECUTED

        return self._build_result(
            decision,
            action=action,
            status=status,
            guard_verdict=guard_decision.verdict,
            guard_rule=guard_decision.rule,
            guard_reason=guard_decision.reason,
            tier=guard_decision.tier,
            idempotency_key=idempotency_key,
            attempts=attempts,
            executor=executor,
            receipt=receipt,
        )

    # ── Revert (invoked by the API, not by the graph) ─────────────────────────

    def revert(self, response: ResponseResult) -> ResponseResult:
        """Roll back a previously executed response.

        Exposed for the API layer so a rollback travels the same executor path
        — and produces the same auditable ResponseResult — as the original
        action, rather than being a list mutation somewhere in the web layer.
        """
        executor = self.executor_registry.resolve(
            response.action.action_type, response.action.target.target_type
        )
        started = time.perf_counter()
        receipt = executor.revert(
            ExecutionReceipt(
                succeeded=True,
                executor_name=response.executor_name or executor.executor_name,
                executor_version=response.executor_version or executor.executor_version,
                external_reference=response.external_reference,
                revert_token=response.revert_token,
            )
        )
        duration_ms = round((time.perf_counter() - started) * 1000.0, 3)

        result = ResponseResult(
            decision_id=response.decision_id,
            correlation_id=response.correlation_id,
            trace_id=response.trace_id,
            action=response.action,
            original_action=response.original_action,
            status=ResponseStatus.REVERTED,
            guard_verdict=GuardVerdict.ALLOW,
            guard_rule="analyst_revert",
            guard_reason=(
                f"Analyst reverted response {response.response_id}. Rollback is "
                "always permitted — it reduces impact."
            ),
            engine_trust_tier=response.engine_trust_tier,
            decision_engine=response.decision_engine,
            executor_name=executor.executor_name,
            executor_version=executor.executor_version,
            idempotency_key=f"revert:{response.response_id}",
            attempts=[
                ExecutionAttempt(
                    attempt_number=1, succeeded=True, duration_ms=duration_ms
                )
            ],
            external_reference=receipt.external_reference,
            reverts_response_id=response.response_id,
            response_duration_ms=duration_ms,
            metadata={
                "agent":               self.agent_name,
                "reverted_response_id": response.response_id,
            },
            audit=AuditMetadata(
                created_by=self.agent_name,
                updated_by=self.agent_name,
                source_system="response_pipeline",
            ),
        )
        self._store_memory(None, result)
        logger.info(
            "response_agent_reverted",
            extra={
                "agent":                self.agent_name,
                "response_id":          result.response_id,
                "reverted_response_id": response.response_id,
            },
        )
        return result

    # ── State traversal ───────────────────────────────────────────────────────

    def _next_decision_for_response(
        self,
        state: PlatformStateModel,
    ) -> DecisionResult | None:
        """Return the first DecisionResult still needing a response.

        AWAITING_APPROVAL is resumable, not terminal, so a decision whose only
        responses have that status remains selectable — otherwise an action an
        analyst approved could never execute.

        This does not risk a loop: the agent still refuses to act without a
        genuine analyst ruling, and CoordinatorAgent attempts a resume at most
        once per run.
        """
        terminal_decision_ids = {
            r.decision_id
            for r in state.response_results
            if r.status is not ResponseStatus.AWAITING_APPROVAL
        }
        for decision in state.decision_results:
            if decision.decision_id not in terminal_decision_ids:
                return decision
        return None

    # ── Approval ──────────────────────────────────────────────────────────────

    def _resolve_human_ruling(self, decision: DecisionResult) -> bool | None:
        """Return True (approved by a human), False (rejected), or None.

        Only a genuine analyst ruling counts. ApprovalStatus.AUTO_APPROVED is
        deliberately NOT treated as human approval: it is the decision engine
        approving its own output, and an LLM must never be able to satisfy the
        gate that exists to supervise it. AUTO_APPROVED still satisfies the
        decision-level gate via ``requires_approval=False`` — it just cannot
        substitute for a human where the trust policy demands one.

        The live approval store is checked first, because an analyst's ruling
        arrives after the state snapshot was taken.
        """
        if self.approval_store is not None:
            try:
                ruling = self.approval_store.get(decision.decision_id)
            except Exception as exc:
                logger.warning(
                    "response_agent_approval_lookup_failed",
                    extra={
                        "agent":       self.agent_name,
                        "decision_id": decision.decision_id,
                        "error":       str(exc),
                    },
                )
                ruling = None
            if ruling is not None:
                return ruling.approved

        if decision.approval_status is ApprovalStatus.REJECTED:
            return False
        if decision.approval_status is ApprovalStatus.APPROVED:
            return True
        return None

    # ── Idempotency ───────────────────────────────────────────────────────────

    @staticmethod
    def _idempotency_key(decision: DecisionResult, action: Action) -> str:
        """Stable key identifying "this action, on this target, in this run".

        Includes correlation_id so an unrelated workflow legitimately acting on
        the same target is not suppressed — repeat offenders across separate
        incidents are bounded by the guard's per-target window instead.
        """
        raw = "|".join(
            [
                action.action_type.value,
                action.target.target_type.upper(),
                action.target.target_value,
                decision.correlation_id,
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _find_duplicate(self, idempotency_key: str) -> str | None:
        """Return the response_id of a recent identical execution, if any."""
        if self.memory_provider is None:
            return None
        window_start = datetime.now(timezone.utc) - timedelta(
            seconds=self.config.idempotency_window_seconds
        )
        try:
            hits = self.memory_provider.search(
                RESPONSE_COLLECTION,
                MemoryQuery(
                    record_types=[_RECORD_TYPE],
                    metadata={"idempotency_key": idempotency_key},
                    created_after=window_start,
                    order_by="created_at",
                    descending=True,
                    limit=1,
                ),
            )
        except Exception as exc:
            logger.warning(
                "response_agent_idempotency_check_failed",
                extra={"agent": self.agent_name, "error": str(exc)},
            )
            return None

        for hit in hits:
            content = hit.record.content if isinstance(hit.record.content, dict) else {}
            # Only a real side-effect suppresses a repeat. A prior failure or
            # guard block must not prevent a legitimate retry.
            if content.get("status") in (
                ResponseStatus.EXECUTED.value,
                ResponseStatus.DOWNGRADED.value,
            ):
                return content.get("response_id")
        return None

    # ── Result construction ───────────────────────────────────────────────────

    def _awaiting_approval(
        self,
        decision: DecisionResult,
        *,
        rule: str,
        reason: str,
        tier: EngineTrustTier | None = None,
    ) -> ResponseResult:
        return self._build_result(
            decision,
            action=decision.action,
            status=ResponseStatus.AWAITING_APPROVAL,
            guard_verdict=GuardVerdict.REQUIRE_APPROVAL,
            guard_rule=rule,
            guard_reason=reason,
            tier=tier or self.guard.trust_policy.tier_for(decision.decision_engine),
        )

    def _build_result(
        self,
        decision: DecisionResult,
        *,
        action: Action,
        status: ResponseStatus,
        guard_verdict: GuardVerdict,
        guard_rule: str,
        guard_reason: str,
        tier: EngineTrustTier,
        idempotency_key: str | None = None,
        attempts: list[ExecutionAttempt] | None = None,
        executor: ResponseExecutor | None = None,
        receipt: ExecutionReceipt | None = None,
        duplicate_of_response_id: str | None = None,
    ) -> ResponseResult:
        """Assemble a fully-linked, validated ResponseResult."""
        return ResponseResult(
            decision_id=decision.decision_id,
            correlation_id=decision.correlation_id,
            trace_id=decision.trace_id,
            action=action,
            original_action=decision.action,
            status=status,
            guard_verdict=guard_verdict,
            guard_rule=guard_rule,
            guard_reason=guard_reason,
            engine_trust_tier=tier,
            decision_engine=decision.decision_engine,
            executor_name=executor.executor_name if executor else None,
            executor_version=executor.executor_version if executor else None,
            idempotency_key=idempotency_key or self._idempotency_key(decision, action),
            attempts=attempts or [],
            external_reference=receipt.external_reference if receipt else None,
            revert_token=receipt.revert_token if receipt else None,
            duplicate_of_response_id=duplicate_of_response_id,
            expires_at=receipt.expires_at if receipt else None,
            response_duration_ms=0.0,  # replaced by __call__ with the measured value
            metadata={
                "agent":              self.agent_name,
                "source_decision_id": decision.decision_id,
                "decision_priority":  decision.priority.value,
                "policy_source":      self.config.source_path or "built_in_defaults",
                **(
                    {"downgraded_from": decision.action.action_type.value}
                    if guard_verdict is GuardVerdict.DOWNGRADE
                    else {}
                ),
            },
            audit=AuditMetadata(
                created_by=self.agent_name,
                updated_by=self.agent_name,
                source_system="response_pipeline",
            ),
        )

    # ── Memory ────────────────────────────────────────────────────────────────

    def _store_memory(
        self,
        decision: DecisionResult | None,
        result: ResponseResult,
    ) -> None:
        """Persist the response for audit, idempotency, and LearningAgent feedback.

        A memory failure is logged and swallowed — losing the audit copy must
        not undo an action that already happened.
        """
        if self.memory_provider is None:
            return
        try:
            record = MemoryRecord(
                backend="qdrant_sqlite",
                collection=RESPONSE_COLLECTION,
                record_type=_RECORD_TYPE,
                entity_id=result.action.target.target_value,
                correlation_id=result.correlation_id,
                trace_id=result.trace_id,
                # Content carries everything needed to rebuild the action for a
                # later revert, plus the full authorisation trail for audit.
                content={
                    "response_id":         result.response_id,
                    "decision_id":         result.decision_id,
                    "correlation_id":      result.correlation_id,
                    "trace_id":            result.trace_id,
                    "status":              result.status.value,
                    "action_type":         result.action.action_type.value,
                    "original_action_type": result.original_action.action_type.value,
                    "target_type":         result.action.target.target_type,
                    "target_value":        result.action.target.target_value,
                    "guard_verdict":       result.guard_verdict.value,
                    "guard_rule":          result.guard_rule,
                    "guard_reason":        result.guard_reason,
                    "engine_trust_tier":   result.engine_trust_tier.value,
                    "decision_engine":     result.decision_engine,
                    "executor_name":       result.executor_name,
                    "executor_version":    result.executor_version,
                    "idempotency_key":     result.idempotency_key,
                    "external_reference":  result.external_reference,
                    "revert_token":        result.revert_token,
                    "reverts_response_id": result.reverts_response_id,
                    "executed_at":         result.executed_at.isoformat(),
                    "expires_at":          result.expires_at.isoformat() if result.expires_at else None,
                    "response_duration_ms": result.response_duration_ms,
                    "attempts":            len(result.attempts),
                },
                metadata={
                    "agent":           self.agent_name,
                    "idempotency_key": result.idempotency_key,
                    "decision_id":     result.decision_id,
                    "status":          result.status.value,
                    "action_type":     result.action.action_type.value,
                    **({"priority": decision.priority.value} if decision else {}),
                },
                tags=[
                    self.agent_name,
                    "response",
                    result.status.value,
                    result.action.action_type.value,
                ],
            )
            self.memory_provider.store(RESPONSE_COLLECTION, record)
        except Exception as exc:
            logger.warning(
                "response_agent_memory_store_failed",
                extra={"agent": self.agent_name, "error": str(exc)},
            )

    # ── State update helpers (mirrors DecisionAgent pattern) ──────────────────

    def _success_update(
        self,
        state: PlatformStateModel,
        result: ResponseResult,
    ) -> PlatformSharedState:
        metadata = self._merged_metadata(
            state.metadata,
            {
                "status":            "completed",
                "last_decision_id":  result.decision_id,
                "last_response_id":  result.response_id,
                "response_count":    len(state.response_results) + 1,
                "response_status":   result.status.value,
                "action_type":       result.action.action_type.value,
                "guard_verdict":     result.guard_verdict.value,
                "guard_rule":        result.guard_rule,
                "engine_trust_tier": result.engine_trust_tier.value,
                "executor":          result.executor_name,
            },
        )
        return PlatformSharedState(
            correlation_id=state.correlation_id,
            trace_id=state.trace_id,
            session_id=state.session_id,
            response_results=[result],
            metadata=metadata,
        )

    def _metadata_update(
        self,
        state: PlatformStateModel,
        *,
        status: str,
        reason: str,
    ) -> PlatformSharedState:
        return PlatformSharedState(
            correlation_id=state.correlation_id,
            trace_id=state.trace_id,
            session_id=state.session_id,
            metadata=self._merged_metadata(
                state.metadata,
                {
                    "status":         status,
                    "reason":         reason,
                    "response_count": len(state.response_results),
                },
            ),
        )

    def _error_update(
        self,
        state: PlatformStateModel | None,
        error: Exception,
    ) -> PlatformSharedState:
        """Return an error state update.

        ``state`` is None when hydration itself failed, so the correlation IDs
        are unavailable — the error is still surfaced rather than swallowed.
        """
        error_metadata = {
            "status":     "failed",
            "error_type": type(error).__name__,
        }
        update: dict[str, Any] = {
            "errors":   [f"{self.agent_name}: {error}"],
            "metadata": self._merged_metadata(
                state.metadata if state else {}, error_metadata
            ),
        }
        if state is not None:
            update.update(
                correlation_id=state.correlation_id,
                trace_id=state.trace_id,
                session_id=state.session_id,
            )
        return PlatformSharedState(**update)

    def _merged_metadata(
        self,
        existing: dict[str, Any],
        response_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        return {**existing, self.agent_name: response_metadata}
