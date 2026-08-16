# LearningAgent Documentation

## Overview

The `LearningAgent` is the outcome-feedback and improvement node of the Cyber Surakshya SOC platform. It is the platform's memory of how well it has been doing, and the only component that can tell an operator whether the other five agents are actually working.

```
OutcomeCollector ─┐
                  ├─► MetricsEngine ─► PatternDiscovery ─► RecommendationEngine ─► LearningReport
FeedbackRecorder ─┘
```

## The five modules

| Module | Produces |
|---|---|
| **OutcomeCollector** | joins detection + analysis + decision + response + approval + feedback into `IncidentHistory` |
| **FeedbackRecorder** | records and reads analyst verdicts — the platform's only ground truth |
| **MetricsEngine** | FP, FN, precision, recall, MTTD, MTTR, decision accuracy, response success, approval rate, guard intervention |
| **PatternDiscovery** | repeat attackers, frequent threats, repeated failures, attack paths, recurring incidents, approval bottlenecks, guard friction |
| **RecommendationEngine** | ranked, advisory proposals — never applied |

### Feedback is an input, not a trailing sink

`FeedbackRecorder` sits *before* `MetricsEngine` in the dataflow, because **false positives, false negatives, and accuracy are undefined without analyst labels.** The platform cannot detect its own mistakes by introspection: a confident wrong answer looks exactly like a confident right one.

This makes analyst feedback the highest-value data the platform holds, and the design treats it as structurally load-bearing rather than as an afterthought. It is also why a failed feedback write is **raised**, not swallowed — unlike almost every other memory failure in this codebase. Losing an audit copy is survivable; silently losing a verdict corrupts every accuracy number computed afterwards, invisibly and permanently.

## Evidence guards

Every metric is a `MetricSummary` carrying `value`, `sample_size`, and `sufficient_data`.

Below `min_sample_size` (default 10) the value is `None` and `sufficient_data` is `False`. **A 93% accuracy computed from two labels is more dangerous than no number at all** — it will be read as fact and acted on. When evidence is missing, the report says so.

The `RecommendationEngine` enforces the same rule: any recommendation whose trigger metric has `sufficient_data=False` is suppressed, and `COLLECT_MORE_FEEDBACK` is emitted instead. The honest output of an unlabelled platform is *"we cannot tell you yet, and here is how to fix that"*.

`feedback_coverage` sits at the top of every report so no consumer reads a ground-truth metric without first seeing what it rests on.

## Incident identity

One incident = **one detection and everything downstream of it**:

```
detection ─► analysis ─► decision ─► response(s) ─► approval ─► feedback
```

`correlation_id` is carried as an attribute but is deliberately **not** the key. Since `CoordinatorAgent` landed, one run shares one `correlation_id` across many events, so keying on it would merge unrelated incidents and destroy every per-incident metric.

Partial chains are preserved rather than discarded — an incident awaiting approval has no terminal response yet, and dropping it would bias every metric toward the cases that completed quickly.

## Metrics reference

| Metric | Ground truth | Notes |
|---|---|---|
| `pipeline_completion_rate` | no | incidents that traversed every stage |
| `threat_detection_rate` | no | non-benign share of incidents |
| `false_positive_rate` | **yes** | rejected threat detections / all threat detections |
| `false_negative_rate` | **yes** | rejected benign detections / actual threats |
| `precision`, `recall`, `detection_accuracy` | **yes** | over labelled incidents only |
| `decision_accuracy` | **yes** | scoped to incidents that produced a decision |
| `mttd_seconds` | no | `detected_at − observed_at` |
| `mttr_seconds` | no | `executed_at − observed_at` |
| `response_success_rate` | no | see exclusion note below |
| `approval_rate` | no | approvals granted / rulings recorded |
| `guard_intervention_rate` | no | how often the safety layer overrode a decision |

### Two exclusions that matter

**`AWAITING_APPROVAL` and `BLOCKED_BY_GUARD` are excluded from `response_success_rate` entirely** — not counted as failures. The response layer refusing to act is it working as designed. Counting those as failures would push the RecommendationEngine toward loosening the very safety gates that are functioning.

**Incidents lacking stage timestamps are excluded from MTTD/MTTR, not defaulted to zero.** Records written before those timestamps were persisted would otherwise report a flawless response time built entirely from missing data.

### A contradictory verdict is excluded, not reinterpreted

`FALSE_POSITIVE` recorded against a *benign* detection is contradictory: nothing was flagged, so there is no positive to be false. Such rulings are counted separately and excluded from the confusion matrix. Folding them into the false-negative count would silently invert the analyst's meaning — corrupting exactly the ground truth the module exists to protect. A warning is logged so the bad label can be corrected.

`NEEDS_REVIEW` is likewise never scored: counting *"we don't know"* as either right or wrong would corrupt every downstream metric.

## It recommends; it never executes

Nothing in `LearningAgent` retrains a model, edits `config/response_policy.yaml`, changes a threshold, or touches an executor. Every output is a sentence describing what a human should consider doing, with the evidence that prompted it.

This mirrors the `DecisionAgent`/`ResponseAgent` split, for the same reason and higher stakes: the actions recommended here — retraining a model, loosening a detection threshold — are exactly the ones that would degrade the platform invisibly if applied automatically from a bad inference. A component that both draws conclusions and acts on them has no review point.

The agent exposes no `apply`, `execute`, or `retrain` method at all; a test asserts this.

## Not a pipeline node

Detection, analysis, decision, and response run **per event**. Learning runs over **history**.

Registering it in the coordinated graph would re-derive platform-wide metrics on every single flow, and make each event's latency grow with the size of the archive. It is invoked on demand via the API, or on a schedule. It keeps a LangGraph-compatible `__call__` for use in a dedicated learning graph, but is **not** registered in the main pipeline.

`PlatformSharedState` gains no `learning_reports` field: a report describes history, not the run that produced it.

## Upstream change this component required

`SecurityEvent.observed_at` existed but was never persisted to memory, so time-to-detect could not be computed from history at all. `DetectionAgent`, `AnalysisAgent`, and `DecisionAgent` now persist their stage timestamps (`observed_at`, `detected_at`, `analyzed_at`, `decided_at`); `ResponseAgent` already persisted `executed_at`. Records predating this change are excluded from timing metrics rather than defaulted.

## API

| Endpoint | Purpose |
|---|---|
| `POST /learning/analyze` | Run a learning cycle and return the report |
| `GET /learning/report` | Most recent persisted report, without recomputing |
| `GET /learning/reports` | Report history, for trend tracking |
| `GET /learning/metrics` | Metrics only, each with its evidence base |
| `GET /learning/patterns` | Discovered patterns |
| `GET /learning/recommendations` | Ranked advisory recommendations |
| `POST /learning/feedback` | Record an analyst verdict |
| `GET /learning/feedback` | Recorded verdicts, newest first |

Verdicts: `CORRECT`, `INCORRECT`, `FALSE_POSITIVE`, `NEEDS_REVIEW`, `ESCALATE`.

```bash
curl -X POST "localhost:8000/learning/feedback?detection_id=<uuid>&verdict=FALSE_POSITIVE&analyst=soc1" \
     -H "X-API-Key: ..."
```

## Usage

```python
from agents.learning import LearningAgent

agent  = LearningAgent(memory_provider)
report = agent.analyze()

print(f"coverage {report.feedback_coverage:.0%} of {report.total_incidents} incidents")
for recommendation in report.recommendations:
    print(f"[{recommendation.priority.value}] {recommendation.summary}")
    print(f"    → {recommendation.suggested_change}")
```

Tuning the evidence floor and pattern thresholds:

```python
from agents.learning import LearningAgent, PatternDiscovery
from agents.learning.pattern_discovery import PatternThresholds

LearningAgent(
    memory_provider,
    min_sample_size=25,                                   # stricter evidence floor
    pattern_discovery=PatternDiscovery(PatternThresholds(repeat_attacker=5)),
)
```

## Running Tests

```bash
pytest tests/agents/test_learning_agent.py tests/agents/test_learning_metrics.py -v
```

## Out of Scope (This Component)

- Automated retraining or model deployment
- Automated policy or threshold changes
- Statistical clustering / anomaly scoring (frequency counting is honest at this sample size; clustering would produce confident-looking noise that the RecommendationEngine would turn into firewall changes)
- Scheduling — the agent is invoked, it does not schedule itself
- Frontend learning dashboard
