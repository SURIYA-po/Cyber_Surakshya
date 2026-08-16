# Implementation Plan: `LearningAgent` (Outcome Feedback & Improvement Node)

> Status: **IMPLEMENTED.** See `docs/learning_agent.md` for the as-built documentation.
> Depends on: `DetectionAgent`, `AnalysisAgent`, `DecisionAgent`, `ResponseAgent`, `CoordinatorAgent` (all complete), `MemoryProvider` (complete).
>
> **Deviations from this plan, decided during implementation:**
> 1. **Contradictory verdicts are excluded from the confusion matrix.** Found while testing against live data: `FALSE_POSITIVE` recorded against a *benign* detection was being binned as a false negative, silently inverting the analyst's meaning. Nothing was flagged, so there is no positive to be false. Such rulings are now counted separately, excluded, and logged as a warning.
> 2. **`sample_size` for ground-truth metrics counts only usable rulings** (`tp+fp+fn+tn`), not every labelled incident, so contradictory verdicts cannot inflate the apparent evidence base.
> 3. **A rate over an empty denominator is `None`, not `0.0`.** With no actual threats in the labelled set, a miss rate is undefined; reporting zero would read as "we miss nothing".
> 4. **`FeedbackStoreError` surfaces as HTTP 400/502 rather than 500.** A malformed `detection_id` is an operator error and must say so, not present as a server fault.

---

## 0. The proposed structure, and three changes to it

The requested five-module architecture is adopted as-is in naming and responsibility:

```
LearningAgent
├── OutcomeCollector       → joins detection + analysis + decision + response into incident history
├── MetricsEngine          → FP, FN, MTTD, MTTR, decision accuracy, response success, approval rate
├── PatternDiscovery       → repeat attackers, frequent threats, repeated failures, attack paths
├── RecommendationEngine   → recommends; never executes
└── FeedbackRecorder       → analyst verdicts: correct / incorrect / needs review / escalate / false positive
```

Three changes, each with a reason:

### Change 1 — FeedbackRecorder is an **input** to MetricsEngine, not a peer beside it

Listed last, `FeedbackRecorder` reads as an output stage. It is not: **false positives, false negatives, and decision accuracy are undefined without analyst labels.** The platform cannot know it was wrong by inspecting its own output — a confident wrong answer looks exactly like a confident right one.

So the dataflow is:

```
OutcomeCollector ─┐
                  ├─► MetricsEngine ─► PatternDiscovery ─► RecommendationEngine ─► LearningReport
FeedbackRecorder ─┘
```

`FeedbackRecorder` still owns writing verdicts (the API path an analyst uses). It simply also feeds metrics. The characterisation that this is "the most valuable data in the entire platform" is exactly right, and the design should make it structurally load-bearing rather than a trailing sink.

### Change 2 — every ground-truth metric carries its sample size, and refuses to report below a floor

With 15 incidents and 2 labeled, "93% accuracy" is worse than no number: it will be read as fact and acted on. Each metric is therefore a `MetricSummary` carrying `value`, `sample_size`, and `sufficient_data`. Below `min_sample_size` (default 10) the value is `None` and `sufficient_data` is `False` — the report says *we do not know yet*, and the RecommendationEngine refuses to emit any recommendation that depends on it.

This is the difference between a learning loop and a random-number generator pointed at a firewall.

### Change 3 — MTTD requires a schema fix first

`SecurityEvent.observed_at` exists but is **not persisted** to the `detections` memory record, so time-to-detect cannot be computed from history at all today. `DetectionAgent`, `AnalysisAgent`, and `DecisionAgent` will persist their stage timestamps (`observed_at`, `detected_at`, `analyzed_at`, `decided_at`); `ResponseAgent` already persists `executed_at`.

Definitions, stated explicitly because "MTTD" is used loosely in the industry:

| Metric | Definition |
|---|---|
| **MTTD** | `detected_at − observed_at` — observation to detection |
| **MTTR** | `response.executed_at − observed_at` — observation to containment |
| **pipeline latency** | per-stage deltas, for locating where time is spent |

Records written before this change lack the fields and are excluded from those metrics rather than defaulted to zero.

---

## 1. Boundary Contract

### DOES
- Read historical records from the `detections`, `analysis`, `decisions`, `responses`, `approvals`, and `feedback` memory collections.
- Join them into per-detection `IncidentHistory` records.
- Compute metrics, discover patterns, and emit ranked recommendations.
- Persist a `LearningReport` to the `learning_reports` collection.
- Record and read analyst feedback.

### DOES NOT
- **Retrain, fine-tune, or modify any model.** It recommends retraining; a human runs `train.py`.
- **Modify policy, thresholds, or `response_policy.yaml`.** It recommends edits.
- Execute any containment action, or influence a live decision.
- Read `PlatformSharedState` results for the current run — it is a historian, not a participant.
- Call an LLM.

The recommend/execute split mirrors `DecisionAgent`/`ResponseAgent`, and for the same reason: a component that both concludes and acts on its conclusions has no review point.

### Not a per-event pipeline node

Detection, analysis, decision, and response run **per event**. Learning runs over **history**. Registering it in the coordinated graph would re-derive platform-wide metrics on every single flow — wasteful, and it would make each event's latency depend on the size of the archive.

`LearningAgent` is therefore invoked on demand (API) or on a schedule. It keeps a LangGraph-compatible `__call__` for consistency and future use in a dedicated learning graph, but is **not** registered in the main pipeline. `PlatformSharedState` gains no `learning_reports` field: a report is a historical artifact, not run state.

---

## 2. Folder Structure

```
cyber_surakshya/platform/schemas/learning_report.py   # NEW
agents/learning/                                       # NEW
├── __init__.py
├── learning_agent.py           # orchestrates the five modules
├── outcome_collector.py        # module 1
├── feedback.py                 # module 5 (an input; see Change 1)
├── metrics_engine.py           # module 2
├── pattern_discovery.py        # module 3
├── recommendation_engine.py    # module 4
└── exceptions.py

agents/detection/detection_agent.py   # EDIT — persist observed_at / detected_at
agents/analysis/analysis_agent.py     # EDIT — persist analyzed_at
agents/decision/decision_agent.py     # EDIT — persist decided_at

tests/agents/test_learning_agent.py   # NEW
tests/agents/test_learning_metrics.py # NEW
docs/learning_agent.md                # NEW
```

---

## 3. Incident Identity

One incident = **one detection and everything downstream of it**:

```
detection (detection_id)
   └─ analysis   where analysis.detection_id  == detection_id
       └─ decision where decision.analysis_id == analysis_id
           └─ response(s) where response.decision_id == decision_id
               └─ approval  where approval.decision_id == decision_id
                   └─ feedback where feedback.detection_id == detection_id
```

`correlation_id` is an **attribute**, not the key. Since `CoordinatorAgent` landed, one run (one `correlation_id`) can carry many events, so keying on it would merge unrelated incidents into one.

Partial chains are normal — an incident may have no response yet — and are preserved rather than discarded, with a `completeness` flag.

---

## 4. Metrics

| Metric | Needs ground truth | Definition |
|---|---|---|
| `total_incidents` | no | joined incident count |
| `detection_rate` | no | non-BENIGN detections / total |
| `false_positive_rate` | **yes** | analyst `FALSE_POSITIVE` or `INCORRECT` on a threat detection |
| `false_negative_rate` | **yes** | analyst `INCORRECT` on a BENIGN detection |
| `precision` / `recall` | **yes** | over labeled incidents only |
| `decision_accuracy` | **yes** | decisions the analyst marked `CORRECT` |
| `mttd_seconds` | no | `detected_at − observed_at` |
| `mttr_seconds` | no | `executed_at − observed_at` |
| `response_success_rate` | no | `EXECUTED`/`DRY_RUN`/`NO_OP`/`DOWNGRADED` over attempted; `AWAITING_APPROVAL` and `BLOCKED_BY_GUARD` are excluded as *not attempted*, not counted as failures |
| `approval_rate` | no | approvals granted / rulings recorded |
| `guard_intervention_rate` | no | `DOWNGRADED` + `BLOCKED_BY_GUARD` over total — how often the safety layer overrode a decision |

`feedback_coverage` (labeled / total) is reported at the top of every report so no consumer reads a ground-truth metric without seeing what it rests on.

---

## 5. Patterns

`repeat_attacker`, `frequent_threat`, `repeated_response_failure`, `common_attack_path` (label → action), `recurring_incident`, `approval_bottleneck`, `guard_friction` (an engine downgraded unusually often). Each carries `occurrences`, `first_seen`, `last_seen`, `entities`, and `confidence`.

## 6. Recommendations

`RAISE_CONFIDENCE_THRESHOLD`, `LOWER_CONFIDENCE_THRESHOLD`, `PREFER_LESS_DISRUPTIVE_ACTION`, `ADD_CONTAINMENT_RULE`, `REVIEW_POLICY`, `RETRAIN_MODEL`, `REVIEW_EXECUTOR`, `TUNE_TRUST_TIER`, `COLLECT_MORE_FEEDBACK`.

Each carries `priority`, `rationale`, `evidence` (the metric or pattern that produced it), and `suggested_change` — never an applied change. Any recommendation whose trigger metric has `sufficient_data=False` is suppressed and replaced by `COLLECT_MORE_FEEDBACK`.

---

## 7. Test Plan

| File | Coverage |
|---|---|
| `test_learning_agent.py` | incident joining incl. partial chains; correlation_id with many events does not merge incidents; feedback write/read round-trip; report persisted to memory; empty history produces an empty report, not a crash; memory failure is contained; recommend-only boundary (no executor/model/policy touched). |
| `test_learning_metrics.py` | each metric's arithmetic on a fixture; `sufficient_data=False` below the floor; ground-truth metrics `None` with zero feedback; `AWAITING_APPROVAL` excluded from response success; MTTD/MTTR skip records lacking timestamps; pattern thresholds; recommendation suppression when evidence is insufficient; `COLLECT_MORE_FEEDBACK` emitted instead. |

---

## 8. Build Order

1. `learning_report.py` schemas.
2. Upstream timestamp persistence (detection, analysis, decision).
3. `outcome_collector.py` + `feedback.py`.
4. `metrics_engine.py`.
5. `pattern_discovery.py` + `recommendation_engine.py`.
6. `learning_agent.py` + API endpoints.
7. Tests, `docs/learning_agent.md`, `OVERVIEW.md`.

Per AI_DEVELOPMENT_RULES §7, work stops after step 7. This completes the six-agent architecture in `docs/project_vision.md`.
