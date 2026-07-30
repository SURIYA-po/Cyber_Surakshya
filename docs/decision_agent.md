# DecisionAgent Documentation

## Overview

The `DecisionAgent` is the policy and decision engine node of the Cyber Surakshya SOC platform. It operates after the `AnalysisAgent` and before the `ResponseAgent`.

```
SecurityEvent ──► DetectionAgent ──► DetectionResult ──► AnalysisAgent ──► AnalysisResult ──► DecisionAgent ──► DecisionResult ──► ResponseAgent
```

## Architectural Boundaries

- **Single Responsibility**: `DecisionAgent` evaluates threat context, memory history, and policy rules to decide *what action SHOULD be recommended* and *whether human approval is required*. It NEVER executes side-effects (firewall updates, IP blocks, host isolation, or external notifications).
- **Decoupled Actions**: Uses the `platform.actions` layer (`Action`, `ActionType`, `ActionTarget`, `ActionParameters`) so adding integrations (CrowdStrike, SentinelOne, Wazuh, SOAR) requires no schema modifications to `DecisionResult`.
- **Extensible Engines**: Depends strictly on the `DecisionEngine` Protocol (`make_decision(context: DecisionContext) -> DecisionDraft`). `DeterministicDecisionEngine` is the rule-based production default; LLM-based engines (`OllamaDecisionEngine`, `ClaudeDecisionEngine`) can be swapped seamlessly.
- **Human-in-the-Loop Governance**: Produces `requires_approval: bool` and `approval_status: ApprovalStatus` (`PENDING`, `APPROVED`, `REJECTED`, `AUTO_APPROVED`), allowing analysts to review high-impact decisions in the dashboard before execution.

## Policy Engine Rules

`DeterministicDecisionEngine` uses generic, data-driven thresholds without hardcoding attack names (DDoS, Botnet, BruteForce):

1. **Critical Risk Auto-Block**: `CRITICAL` severity + `risk >= 80` ──► `ActionType.BLOCK_IP` (`AUTO_APPROVED`, `requires_approval=False`).
2. **Repeat Offender Isolation**: Entity with `memory_hits >= 2` ──► `ActionType.ISOLATE_HOST` (`PENDING`, `requires_approval=True`).
3. **High Confidence SOC Notification**: `HIGH` severity + `confidence >= 0.75` ──► `ActionType.NOTIFY_SOC` (`AUTO_APPROVED`, `requires_approval=False`).
4. **Medium Risk Rate Limit**: `MEDIUM` severity + `DETECTED` status ──► `ActionType.RATE_LIMIT` (`AUTO_APPROVED`, `requires_approval=False`).
5. **Inconclusive Review**: `INCONCLUSIVE` status ──► `ActionType.NOTIFY_SOC` (`AUTO_APPROVED`, `requires_approval=False`).
6. **Benign Traffic Log**: `BENIGN` status ──► `ActionType.LOG_ONLY` (`AUTO_APPROVED`, `requires_approval=False`).

## Audit & Traceability

Every `DecisionResult` records:
- `policy_version`, `decision_engine`, `engine_version`, `policy_name`
- `decision_duration_ms` (execution timing)
- `memory_hits` (count of prior incidents retrieved from `MemoryProvider`)
- Standard `correlation_id` and `trace_id` propagated from the originating `SecurityEvent`.
