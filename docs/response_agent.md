# ResponseAgent Documentation

## Overview

The `ResponseAgent` is the execution and containment node of the Cyber Surakshya SOC platform. It operates after the `DecisionAgent` and is the **only** component in the platform capable of producing a real-world side-effect.

```
SecurityEvent ──► DetectionAgent ──► AnalysisAgent ──► DecisionAgent ──► DecisionResult ──► ResponseAgent ──► ResponseResult
```

Everything upstream decides what *should* happen. `ResponseAgent` decides what is *allowed* to happen, and then makes it happen.

## Architectural Boundaries

- **Single Input Contract**: reads `DecisionResult` exclusively. It never reads `AnalysisResult`, `DetectionResult`, or `SecurityEvent`. Adding a field to detection or analysis can never break the response layer.
- **No Policy Re-evaluation**: it does not decide *what* to do — that is `DecisionAgent`'s job. The guard may **deny** or **downgrade** an action; it may never **escalate** to something more destructive.
- **Decoupled Execution**: depends on the `ResponseExecutor` abstraction (`adapters/response/base.py`). Adding an integration (iptables, pfSense, AWS Security Groups, CrowdStrike, SentinelOne, Wazuh, TheHive) is one new module plus one registry line. No agent, schema, or guard change.
- **Deterministic by Design**: `ResponseAgent` never calls an LLM. The AI lives in the *decision* engine; execution is deliberately mechanical and auditable.
- **Simulation-Safe by Default**: only `SimulatedContainmentExecutor` and `NotificationExecutor` ship. No module in `adapters/response/` imports a network client, subprocess, or cloud SDK.

## Handling AI-Based Decision Engines

`DecisionAgent` treats engines as interchangeable behind the `DecisionEngine` Protocol. That is correct for decision-making and unsafe for execution: a rule table has a bounded output space, a language model does not. `ResponseAgent` is where that gap is closed.

### Engine Trust Tiers

Execution authority is a function of `DecisionResult.decision_engine`, resolved through `config/response_policy.yaml`.

| Tier | Destructive actions | Min confidence | Behaviour |
|---|---|---|---|
| `DETERMINISTIC` | allowed | 0.70 | `DeterministicDecisionEngine`. Current behaviour, unchanged. |
| `AI_SUPERVISED` | **require a human** | 0.90 | Every LLM engine. Non-destructive verbs (`NOTIFY_SOC`, `OPEN_TICKET`, `ENRICH_THREAT_INTEL`, `LOG_ONLY`) still execute unassisted, so the engine stays useful. |
| `AI_AUTONOMOUS` | allowed | 0.95 | Opt-in only, for a validated model. |
| `UNKNOWN` | denied → downgraded | unsatisfiable | Any unregistered engine. Fail-closed. |

**Critical detail:** `ApprovalStatus.AUTO_APPROVED` is *not* treated as human approval. It is the decision engine approving its own output. An LLM must never be able to satisfy the gate that exists to supervise it. `AUTO_APPROVED` still satisfies the decision-level gate via `requires_approval=False`; it simply cannot substitute for a human where the trust policy demands one.

### Structural Re-validation

An LLM-produced `Action` is Pydantic-valid but not necessarily sane. Before execution the guard checks that `target_value` parses as the type it claims (IP, hostname, path, PID) and that the verb is meaningful for that target class. `BLOCK_IP` on a `FILE` target is denied, not attempted.

### Blast Radius

Bounds what a looping or hallucinating engine can do: max destructive actions per correlation (3), per target per window (900 s), and a platform-wide circuit breaker (10/min) that downgrades everything to `NOTIFY_SOC` and logs an error when tripped.

### Idempotency

LLM output is non-deterministic and graph replays are possible. Each action is keyed by `sha256(action_type | target_type | target_value | correlation_id)`. A repeat inside the window returns `DEDUPLICATED` referencing the original — checked *before* the guard, so a replay does not consume blast-radius budget.

> Switching `DecisionAgent` to an LLM engine requires **zero** `ResponseAgent` code changes — only a `config/response_policy.yaml` entry. `tests/agents/test_action_guard.py::test_enabling_an_llm_engine_is_configuration_only` asserts this.

## Execution Flow

```
1. hydrate PlatformStateModel
2. select first DecisionResult with no ResponseResult   → none ⇒ metadata-only "skipped"
3. rejection check    (analyst ruling or ApprovalStatus.REJECTED)  ⇒ NO_OP
4. approval gate      (requires_approval and no human ruling)      ⇒ AWAITING_APPROVAL
5. idempotency        (identical action inside the window)         ⇒ DEDUPLICATED
6. safety gate        ActionGuard.evaluate()
                         DENY             ⇒ BLOCKED_BY_GUARD
                         REQUIRE_APPROVAL ⇒ AWAITING_APPROVAL
                         DOWNGRADE        ⇒ substitute, continue
7. LOG_ONLY short-circuit                                          ⇒ NO_OP
8. resolve executor by (ActionType, target_type)
9. execute with timeout and bounded retry (transient errors only)
10. build ResponseResult, persist to memory, return state update
```

Failure handling mirrors `DecisionAgent`: a broad `except` appends to `state.errors` and `metadata["response_agent"]`. The node never raises into the graph.

## Two Structural Decisions

### DecisionResult is never mutated

`DecisionStatus.EXECUTED` / `FAILED` exist in the enum, but `PlatformSharedState` list fields use `Annotated[list, operator.add]` append reducers — in-place mutation would break the reducer contract and destroy the append-only audit trail.

**A decision's effective lifecycle is a projection**: join `response_results` on `decision_id`. `DecisionResult.status` keeps the value assigned at decision time. Read this alongside `docs/decision_agent.md` — the enum is not a mutable field.

### Approvals live outside graph state

A run ending in `AWAITING_APPROVAL` terminates; the analyst rules minutes later. The frozen state snapshot cannot carry that, so `ApprovalStore` (memory-backed, `approvals` collection) is queried live at execution time. A later graph run picks the approval up.

A memory outage returns "undecided", which blocks execution rather than allowing it.

## Response Statuses

| Status | Meaning |
|---|---|
| `EXECUTED` | An executor confirmed the side-effect. |
| `DRY_RUN` | Simulated only; no side-effect. |
| `AWAITING_APPROVAL` | Deferred to an analyst. Resumable. |
| `BLOCKED_BY_GUARD` | Safety gate denied it. Terminal. |
| `DOWNGRADED` | A less destructive substitute executed instead. |
| `DEDUPLICATED` | Identical action already ran; original referenced. |
| `NO_OP` | `LOG_ONLY`, or a rejected decision. |
| `FAILED` | Executor raised or timed out after retries. |
| `REVERTED` | Rolled back a prior response. |

`ResponseResult` enforces coherence between these at construction: `BLOCKED_BY_GUARD` cannot carry execution attempts, `DOWNGRADED` requires `action != original_action`, `DEDUPLICATED` requires a `duplicate_of_response_id`, and so on. An incoherent record is unconstructible.

## Configuration

`config/response_policy.yaml` — trust tiers, destructive verb list, protected targets, blast radius, timeouts, duration bounds. See `agents/response/config.py` for the fail-closed defaults.

**Fail-closed contract:** every failure path — missing file, malformed YAML, missing PyYAML, unknown enum value — yields the built-in defaults, which are the strictest configuration supported. Two invariants are not operator-overridable:

1. `UNKNOWN` tier can never be widened to allow destructive actions.
2. `downgrade_action` can never be set to a destructive verb.

## Audit Trail

Every `ResponseResult` records `guard_verdict`, `guard_rule`, `guard_reason`, `engine_trust_tier`, `decision_engine`, `executor_name`, `idempotency_key`, and every `ExecutionAttempt` with timing and error detail. Records are persisted to the `responses` memory collection — which is also the feedback source a future `LearningAgent` will consume.

## API

| Endpoint | Purpose |
|---|---|
| `GET /response/actions?status=` | List response actions. |
| `GET /response/actions/{response_id}` | Detail including guard verdict and attempts. |
| `GET /response/pending-approvals` | HITL queue. |
| `POST /response/actions/{decision_id}/approve` | Record analyst approval. |
| `POST /response/actions/{decision_id}/reject` | Terminal rejection. |
| `GET /response/policy` | Inspect the active authorisation policy. |
| `GET /blocked-ips` | Active containments, projected from `ResponseResult`. |
| `DELETE /blocked-ips/{response_id}` | Real revert through the issuing executor. |

`/blocked-ips` previously read a `MOCK_BLOCKED_IPS` list mutated inline in `simulate_attack`. It is now a projection over executed, un-reverted containments, and `DELETE` performs a genuine rollback that produces its own audited `ResponseResult`. The frontend contract is unchanged.

## LangGraph Usage

```python
from adapters.response import build_default_registry
from agents.response import ActionGuard, ResponseAgent, ResponsePolicyConfig
from agents.response.approval import MemoryApprovalStore

policy = ResponsePolicyConfig.load()
builder.register_node(
    "response",
    ResponseAgent(
        build_default_registry(),
        guard=ActionGuard(policy),
        approval_store=MemoryApprovalStore(memory_provider),
        memory_provider=memory_provider,
        config=policy,
    ),
)
```

Pipeline order: `detection → analysis → decision → response`.

## Extending

| Goal | Change required |
|---|---|
| Real firewall / EDR / SOAR integration | New module in `adapters/response/`, one `registry.register(..., override=True)` line. |
| Host or application-layer detection adapter | Nothing here. An `EndpointExecutor` claims `ISOLATE_HOST`/`TERMINATE_PROCESS` for `HOST`/`PROCESS` targets. |
| LLM decision engine | One `engine_trust` entry in the YAML. |
| New action verb | Add to `ActionType`, add a coherence entry in `guard.py`, claim it in an executor. |
| Asset criticality gating | Already implemented; activates automatically once `AssetInventory` populates `ActionTarget.asset_criticality`. |

## Running Tests

```bash
pytest tests/agents/test_response_agent.py tests/agents/test_action_guard.py \
       tests/adapters/test_response_executors.py -v
```

## Out of Scope (This Component)

- CoordinatorAgent, LearningAgent
- Real firewall, EDR, SOAR, or notification integrations
- Asset inventory
- Frontend response/approval pages
