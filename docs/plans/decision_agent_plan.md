# Implementation Plan: `DecisionAgent` (Policy & Decision Node)

## Architecture & Dependency Review

### Architectural Analysis: Option A vs. Option B

#### Option A (Direct Response Coupling):
`DetectionAgent` → `AnalysisAgent` → `ResponseAgent`
- **Flaws**: Forces `ResponseAgent` to both evaluate governance/policy rules *and* execute infrastructure mitigation actions (firewall rules, IP blocks, host isolation).
- **Violations**: Violates the **Single Responsibility Principle (SRP)**, mixes domain decision logic with outbound infrastructure side-effects, and makes Human-in-the-Loop (HITL) analyst approvals messy to decouple.

#### Option B (Decoupled Decision Node — Recommended):
`DetectionAgent` → `AnalysisAgent` → `DecisionAgent` → `ResponseAgent`
- **Advantages**:
  - **Single Responsibility Principle**: `DecisionAgent` evaluates threat severity, confidence, organization policy, and historical memory to decide *what* should be done and *whether* approval is required. `ResponseAgent` (future) executes the decision.
  - **Hexagonal Architecture**: `DecisionAgent` is pure domain logic with zero external infrastructure dependencies.
  - **HITL Governance**: Produces an explicit `DecisionResult` schema where `requires_approval=True` allows SOC analysts to review decisions before execution.
  - **Deterministic & Testable**: 100% unit-testable without mocking network drivers or security tools.

---

## 1. Responsibilities of `DecisionAgent`

### Must Do:
- Consume `AnalysisResult` and `DetectionResult` from `PlatformStateModel`.
- Query `MemoryProvider` for historical decision/threat records associated with the entity or source IP.
- Evaluate deterministic policy rules via `DecisionPolicyEngine`.
- Determine the recommended action (e.g. `BLOCK_IP`, `ISOLATE_HOST`, `RATE_LIMIT`, `QUARANTINE_FILE`, `LOG_ONLY`, `NOTIFY_SOC`).
- Determine execution priority (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Determine analyst approval requirements (`requires_approval: bool`).
- Produce a validated `DecisionResult` and append it to `state.decision_results`.

### Must NOT Do:
- Execute firewall rules, iptables commands, or security group updates.
- Isolate hosts or terminate network connections.
- Send external emails, Slack messages, or webhook notifications.
- Mutate external security products or infrastructure.
- Perform graph orchestration, conditional routing, or coordinator behavior.

---

## 2. New Platform Schemas

#### `cyber_surakshya/platform/schemas/decision_result.py`
- `RecommendedAction` Enum (`BLOCK_IP`, `UNBLOCK_IP`, `ISOLATE_HOST`, `RATE_LIMIT`, `QUARANTINE_FILE`, `NOTIFY_SOC`, `LOG_ONLY`)
- `DecisionPriority` Enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- `DecisionResult` Pydantic model (`decision_id`, `analysis_id`, `event_id`, `correlation_id`, `trace_id`, `recommended_action`, `priority`, `requires_approval`, `approved`, `rationale`, `confidence`, `created_at`, `audit`)

#### `cyber_surakshya/platform/state.py`
- Add `decision_results: list[DecisionResult]` to `PlatformStateModel` and `PlatformSharedState`.

---

## 3. Policy Engine (`DecisionPolicyEngine`)

#### `agents/decision/policy.py`
- Deterministic & rule-based engine (no LLM).
- Evaluates risk, severity, confidence, and prior offense history from `MemoryProvider`.

---

## 4. Memory Integration
- Depends strictly on abstract `MemoryProvider` protocol (`memory/base.py`).

---

## 5. LangGraph Integration
- `agents/decision/decision_agent.py` inherits from `AgentNode`.
- Pipeline sequence in `graph/builder.py`: `detection` → `analysis` → `decision`.

---

## 6. Testing & Documentation Plan
- `tests/agents/test_decision_agent.py`: unit tests for policy evaluation, approval flags, memory lookup, and graph integration.
- Update `OVERVIEW.md` and add `docs/agents/decision_agent.md`.
