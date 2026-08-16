"""Tests for ResponseAgent — the node that turns a decision into an action."""
from __future__ import annotations

from dataclasses import replace

import pytest

from adapters.response import build_default_registry
from adapters.response.base import (
    ExecutionReceipt,
    PermanentExecutorError,
    ResponseExecutor,
    TransientExecutorError,
)
from adapters.response.registry import ExecutorRegistry
from agents.response.approval import InMemoryApprovalStore
from agents.response.guard import ActionGuard
from agents.response.response_agent import ResponseAgent
from cyber_surakshya.platform.actions.action_type import ActionType
from cyber_surakshya.platform.schemas.decision_result import ApprovalStatus
from cyber_surakshya.platform.schemas.response_result import (
    EngineTrustTier,
    GuardVerdict,
    ResponseResult,
    ResponseStatus,
)
from cyber_surakshya.platform.state import PlatformStateModel, create_initial_state
from tests.agents.conftest import (
    DETERMINISTIC_ENGINE,
    LLM_ENGINE,
    UNREGISTERED_ENGINE,
    make_decision,
    make_state,
)


@pytest.fixture
def agent(policy):
    """A ResponseAgent wired with the shipped simulation-safe executors."""
    return ResponseAgent(
        build_default_registry(),
        guard=ActionGuard(policy),
        approval_store=InMemoryApprovalStore(),
        config=policy,
    )


def _response_of(update) -> ResponseResult:
    assert update["response_results"], "expected exactly one ResponseResult"
    return update["response_results"][0]


# ── Happy path ────────────────────────────────────────────────────────────────


def test_auto_approved_decision_executes(agent):
    decision = make_decision()

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.EXECUTED
    assert result.guard_verdict is GuardVerdict.ALLOW
    assert result.executor_name == "SimulatedContainmentExecutor"
    assert result.external_reference is not None
    assert result.revert_token is not None
    assert result.decision_id == decision.decision_id
    assert [a.succeeded for a in result.attempts] == [True]


def test_result_preserves_lineage_and_audit(agent):
    decision = make_decision()

    result = _response_of(agent(make_state(decision)))

    assert result.correlation_id == decision.correlation_id
    assert result.trace_id == decision.trace_id
    assert result.audit.created_by == "response_agent"
    assert result.metadata["source_decision_id"] == decision.decision_id
    assert result.response_duration_ms >= 0.0


def test_state_update_shape_matches_agent_convention(agent):
    decision = make_decision()

    update = agent(make_state(decision))

    assert set(update) == {
        "correlation_id", "trace_id", "session_id", "response_results", "metadata",
    }
    node_metadata = update["metadata"]["response_agent"]
    assert node_metadata["status"] == "completed"
    assert node_metadata["response_status"] == ResponseStatus.EXECUTED.value
    assert node_metadata["guard_verdict"] == GuardVerdict.ALLOW.value
    assert node_metadata["engine_trust_tier"] == EngineTrustTier.DETERMINISTIC.value


def test_notification_action_routes_to_notification_executor(agent):
    decision = make_decision(action_type=ActionType.NOTIFY_SOC)

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.EXECUTED
    assert result.executor_name == "NotificationExecutor"
    assert result.revert_token is None      # an alert cannot be un-sent


def test_log_only_never_reaches_an_executor(agent):
    decision = make_decision(action_type=ActionType.LOG_ONLY)

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.NO_OP
    assert result.executor_name is None
    assert result.attempts == []


# ── Selection ─────────────────────────────────────────────────────────────────


def test_no_pending_decision_yields_metadata_only_update(agent):
    state = create_initial_state().to_graph_state()

    update = agent(state)

    assert "response_results" not in update
    assert update["metadata"]["response_agent"]["status"] == "skipped"
    assert update["metadata"]["response_agent"]["reason"] == "no_pending_decision_results"


def test_already_responded_decision_is_not_reprocessed(agent):
    decision = make_decision()
    first = _response_of(agent(make_state(decision)))

    model = PlatformStateModel.from_graph_state(make_state(decision))
    model.response_results = [first]
    update = agent(model.to_graph_state())

    assert "response_results" not in update
    assert update["metadata"]["response_agent"]["status"] == "skipped"


def test_first_undecided_decision_is_selected(agent):
    first, second = make_decision(target_value="203.0.113.11"), make_decision(
        target_value="203.0.113.12"
    )

    result = _response_of(agent(make_state(first, second)))

    assert result.decision_id == first.decision_id


# ── Approval gate ─────────────────────────────────────────────────────────────


def test_decision_requiring_approval_is_deferred(agent):
    decision = make_decision(
        requires_approval=True, approval_status=ApprovalStatus.PENDING
    )

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.AWAITING_APPROVAL
    assert result.guard_rule == "decision_requires_approval"
    assert result.attempts == []
    assert result.executor_name is None


def test_analyst_approval_resumes_execution(agent):
    decision = make_decision(
        requires_approval=True, approval_status=ApprovalStatus.PENDING
    )
    state = make_state(decision)
    assert _response_of(agent(state)).status is ResponseStatus.AWAITING_APPROVAL

    agent.approval_store.approve(decision.decision_id, approved_by="analyst@soc")
    result = _response_of(agent(state))

    assert result.status is ResponseStatus.EXECUTED
    assert result.executor_name == "SimulatedContainmentExecutor"


def test_analyst_rejection_is_terminal(agent):
    decision = make_decision(
        requires_approval=True, approval_status=ApprovalStatus.PENDING
    )
    agent.approval_store.reject(decision.decision_id, approved_by="analyst@soc")

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.NO_OP
    assert result.guard_rule == "analyst_rejected"
    assert result.attempts == []


def test_decision_rejected_upstream_is_not_executed(agent):
    decision = make_decision(
        requires_approval=True, approval_status=ApprovalStatus.REJECTED
    )

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.NO_OP
    assert result.guard_rule == "analyst_rejected"


def test_approval_store_failure_blocks_rather_than_allows(agent):
    """A memory outage must not become an authorisation."""

    class BrokenStore:
        def get(self, decision_id):
            raise RuntimeError("memory unavailable")

    agent.approval_store = BrokenStore()
    decision = make_decision(
        requires_approval=True, approval_status=ApprovalStatus.PENDING
    )

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.AWAITING_APPROVAL


# ── AI decision engine handling (§2) ──────────────────────────────────────────


def test_llm_destructive_action_is_deferred_to_an_analyst(agent):
    decision = make_decision(
        decision_engine=LLM_ENGINE,
        approval_status=ApprovalStatus.AUTO_APPROVED,
        requires_approval=False,
    )

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.AWAITING_APPROVAL
    assert result.engine_trust_tier is EngineTrustTier.AI_SUPERVISED
    assert result.executor_name is None


def test_llm_notification_executes_unassisted(agent):
    decision = make_decision(decision_engine=LLM_ENGINE, action_type=ActionType.NOTIFY_SOC)

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.EXECUTED
    assert result.engine_trust_tier is EngineTrustTier.AI_SUPERVISED


def test_unregistered_engine_is_downgraded_and_records_the_substitution(agent):
    decision = make_decision(decision_engine=UNREGISTERED_ENGINE)

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.DOWNGRADED
    assert result.action.action_type is ActionType.NOTIFY_SOC
    assert result.original_action.action_type is ActionType.BLOCK_IP
    assert result.metadata["downgraded_from"] == ActionType.BLOCK_IP.value
    assert result.executor_name == "NotificationExecutor"


# ── Guard outcomes ────────────────────────────────────────────────────────────


def test_guard_denial_records_no_execution_attempt(agent):
    decision = make_decision(target_value="127.0.0.1")

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.BLOCKED_BY_GUARD
    assert result.guard_verdict is GuardVerdict.DENY
    assert result.guard_rule == "protected_target"
    assert result.attempts == []
    assert result.executor_name is None


def test_dry_run_executes_without_side_effect(policy):
    agent = ResponseAgent(
        build_default_registry(),
        guard=ActionGuard(replace(policy, dry_run=True)),
        config=replace(policy, dry_run=True),
    )
    decision = make_decision()

    result = _response_of(agent(make_state(decision)))

    assert result.status is ResponseStatus.DRY_RUN
    assert result.external_reference is None
    executor = agent.executor_registry.resolve(ActionType.BLOCK_IP, "IP")
    assert executor.active_entries() == ()


# ── Executor failures ─────────────────────────────────────────────────────────


def test_missing_executor_fails_without_crashing_the_graph(policy):
    agent = ResponseAgent(
        ExecutorRegistry(),                     # nothing registered
        guard=ActionGuard(policy),
        config=policy,
    )

    result = _response_of(agent(make_state(make_decision())))

    assert result.status is ResponseStatus.FAILED
    assert result.attempts[0].error_type == "MissingExecutorError"


def test_transient_failure_is_retried_then_reported(policy):
    class FlakyExecutor(ResponseExecutor):
        executor_name    = "FlakyExecutor"
        executor_version = "1.0.0"
        action_targets   = {ActionType.BLOCK_IP: frozenset({"IP"})}

        def __init__(self):
            self.calls = 0

        def execute(self, request):
            self.calls += 1
            raise TransientExecutorError("upstream timeout")

    executor = FlakyExecutor()
    registry = ExecutorRegistry()
    registry.register(executor)
    agent = ResponseAgent(registry, guard=ActionGuard(policy), config=policy)

    result = _response_of(agent(make_state(make_decision())))

    assert result.status is ResponseStatus.FAILED
    assert executor.calls == policy.max_retries + 1
    assert len(result.attempts) == policy.max_retries + 1
    assert all(not a.succeeded for a in result.attempts)


def test_transient_failure_then_success_is_recorded_as_executed(policy):
    class RecoveringExecutor(ResponseExecutor):
        executor_name    = "RecoveringExecutor"
        executor_version = "1.0.0"
        action_targets   = {ActionType.BLOCK_IP: frozenset({"IP"})}

        def __init__(self):
            self.calls = 0

        def execute(self, request):
            self.calls += 1
            if self.calls == 1:
                raise TransientExecutorError("first attempt timed out")
            return ExecutionReceipt(
                succeeded=True,
                executor_name=self.executor_name,
                executor_version=self.executor_version,
                external_reference="fw-rule-42",
            )

    registry = ExecutorRegistry()
    registry.register(RecoveringExecutor())
    agent = ResponseAgent(registry, guard=ActionGuard(policy), config=policy)

    result = _response_of(agent(make_state(make_decision())))

    assert result.status is ResponseStatus.EXECUTED
    assert result.external_reference == "fw-rule-42"
    assert [a.succeeded for a in result.attempts] == [False, True]


def test_permanent_failure_is_not_retried(policy):
    class RejectingExecutor(ResponseExecutor):
        executor_name    = "RejectingExecutor"
        executor_version = "1.0.0"
        action_targets   = {ActionType.BLOCK_IP: frozenset({"IP"})}

        def __init__(self):
            self.calls = 0

        def execute(self, request):
            self.calls += 1
            raise PermanentExecutorError("target rejected by firewall")

    executor = RejectingExecutor()
    registry = ExecutorRegistry()
    registry.register(executor)
    agent = ResponseAgent(registry, guard=ActionGuard(policy), config=policy)

    result = _response_of(agent(make_state(make_decision())))

    assert result.status is ResponseStatus.FAILED
    assert executor.calls == 1, "a permanent failure must not be retried"


def test_hydration_failure_surfaces_as_an_error_not_an_exception(agent):
    update = agent({"correlation_id": "not-a-uuid"})

    assert update["errors"]
    assert update["metadata"]["response_agent"]["status"] == "failed"


# ── Memory ────────────────────────────────────────────────────────────────────


def test_response_is_persisted_for_audit_and_learning(policy):
    class RecordingMemory:
        def __init__(self):
            self.stored = []

        def store(self, collection, record):
            self.stored.append((collection, record))
            return record

        def search(self, collection, query):
            return []

    memory = RecordingMemory()
    agent = ResponseAgent(
        build_default_registry(),
        guard=ActionGuard(policy),
        memory_provider=memory,
        config=policy,
    )

    result = _response_of(agent(make_state(make_decision())))

    assert len(memory.stored) == 1
    collection, record = memory.stored[0]
    assert collection == "responses"
    assert record.content["response_id"] == result.response_id
    assert record.content["guard_verdict"] == GuardVerdict.ALLOW.value
    assert record.metadata["idempotency_key"] == result.idempotency_key


def test_memory_failure_does_not_undo_a_completed_action(policy):
    class BrokenMemory:
        def store(self, collection, record):
            raise RuntimeError("disk full")

        def search(self, collection, query):
            return []

    agent = ResponseAgent(
        build_default_registry(),
        guard=ActionGuard(policy),
        memory_provider=BrokenMemory(),
        config=policy,
    )

    result = _response_of(agent(make_state(make_decision())))

    assert result.status is ResponseStatus.EXECUTED


def test_identical_action_within_window_is_deduplicated(policy):
    class ReplayMemory:
        def __init__(self):
            self.records = []

        def store(self, collection, record):
            self.records.append(record)
            return record

        def search(self, collection, query):
            from memory.models import MemorySearchResult

            wanted = query.metadata.get("idempotency_key")
            return [
                MemorySearchResult(record=r, score=1.0)
                for r in reversed(self.records)
                if r.metadata.get("idempotency_key") == wanted
            ]

    agent = ResponseAgent(
        build_default_registry(),
        guard=ActionGuard(policy),
        memory_provider=ReplayMemory(),
        config=policy,
    )
    decision = make_decision()
    state = make_state(decision)

    first = _response_of(agent(state))
    second = _response_of(agent(state))

    assert first.status is ResponseStatus.EXECUTED
    assert second.status is ResponseStatus.DEDUPLICATED
    assert second.duplicate_of_response_id == first.response_id


# ── Revert ────────────────────────────────────────────────────────────────────


def test_revert_rolls_back_a_containment(agent):
    executed = _response_of(agent(make_state(make_decision(target_value="203.0.113.99"))))
    executor = agent.executor_registry.resolve(ActionType.BLOCK_IP, "IP")
    assert executor.is_contained("203.0.113.99", ActionType.BLOCK_IP)

    reverted = agent.revert(executed)

    assert reverted.status is ResponseStatus.REVERTED
    assert reverted.reverts_response_id == executed.response_id
    assert not executor.is_contained("203.0.113.99", ActionType.BLOCK_IP)


def test_reverting_a_notification_is_refused(agent):
    """The platform must not claim to have un-sent an alert."""
    from adapters.response.base import RevertNotSupportedError

    notified = _response_of(agent(make_state(make_decision(action_type=ActionType.NOTIFY_SOC))))

    with pytest.raises(RevertNotSupportedError):
        agent.revert(notified)
