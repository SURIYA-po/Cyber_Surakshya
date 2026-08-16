# CoordinatorAgent Documentation

## Overview

The `CoordinatorAgent` is the routing and flow-control node of the Cyber Surakshya SOC platform. It is the hub every other agent returns to, and the only agent that appends **no** records to state.

```
START ──► coordinator ──┬──► detection ──┐
                        ├──► analysis  ──┤
                        ├──► decision  ──┼──► back to coordinator
                        ├──► response  ──┘
                        └──► END
```

## Why It Exists

Every agent in the platform processes **exactly one** pending item per invocation — `DetectionAgent._next_event_for_detection`, `AnalysisAgent`, `DecisionAgent._next_analysis_for_decision`, and `ResponseAgent._next_decision_for_response` all return the first unprocessed record and stop. The graph was a single linear pass.

Those two correct-in-isolation facts combined into silent data loss:

```
events in       : 3          events in       : 3
detections out  : 1          detections out  : 3
analyses out    : 1    →     analyses out    : 3
decisions out   : 1          decisions out   : 3
responses out   : 1          responses out   : 3
   (before)                      (after)
```

Two security events were accepted, never examined, and never reported as skipped. For an IDS platform that is the most serious class of defect there is — a missed detection leaving no trace. `tests/graph/test_coordinator_graph.py` pins both halves: the coordinated graph drains, and the linear graph still drops, so the regression cannot silently return.

## Architectural Boundaries

- **Routes, never works.** It computes *whether a stage should run next*, never *what that stage should do*. It reads no features, labels, risk scores, or actions.
- **Appends nothing.** Its state update contains only `correlation_id`, `trace_id`, `session_id`, and `metadata`. A test asserts this exact key set.
- **No infrastructure.** No executor, memory provider, or LLM. `agents/coordinator/routing.py` is pure functions over state and imports no LangGraph.
- **Stateless instance.** All bookkeeping lives in `metadata["coordinator_agent"]`, because `app.py` holds agents as module-level singletons shared across requests and threads. Counters on `self` would leak between runs.

## Routing Policy

Pure function of state, evaluated in pipeline order; first available, unstalled stage with pending work wins.

| Order | Stage | Pending when |
|---|---|---|
| 1 | `detection` | a `SecurityEvent` has no `DetectionResult` |
| 2 | `analysis` | a `DetectionResult` has no `AnalysisResult` |
| 3 | `decision` | an `AnalysisResult` has no `DecisionResult` |
| 4 | `response` | a `DecisionResult` has no `ResponseResult` |
| 5 | `response` (resume) | a decision's only responses are `AWAITING_APPROVAL`, and resume has not been attempted this run |
| — | `END` | nothing pending, or everything remaining is stalled |

This drains breadth-first — all detections, then all analyses, and so on. Batching per stage suits stages with fixed setup cost (model inference) and keeps the rule a simple ordered scan.

## Termination Safety

Adding a loop to a graph whose nodes swallow their own exceptions creates a live-lock risk that did not previously exist. `DetectionAgent`, on failure, appends to `state.errors` and returns **without** a `DetectionResult`; the event stays pending forever. A naive "route while work remains" loop would dispatch to it indefinitely.

Three guarantees, in precedence order:

**1. Stall detection** — the one that matters. Before dispatching, the coordinator records the target stage's output-list length. If the stage returns and the length is unchanged, that stage is marked stalled, excluded from routing for the rest of the run, and reported in `anomalies`. An infinite loop becomes a visible, attributable failure with the outstanding work still counted in `pending_total`.

**2. Iteration budget** — `max_iterations` (default 100) caps dispatches per run. A backstop; reaching it is itself recorded as an anomaly.

**3. Stage availability** — the coordinator routes only to stages the graph registers. A partial pipeline that omits `decision` would otherwise produce a bare `KeyError` inside LangGraph's branch resolution, mid-run and unattributable. `GraphBuilder` also validates `routable_targets` against registered nodes at **build** time.

### Recursion limit

Each work item costs two super-steps (agent + coordinator). `GraphConfig.recursion_limit` defaults to 25, which a three-event run exceeds. `GraphConfig.effective_recursion_limit(coordinated=True)` derives the limit from `coordinator_max_iterations`, so the coordinator's own budget stops a run and its termination report stays the authoritative explanation. An explicitly larger `recursion_limit` still wins.

## Deduplication

Exact `event_id` duplicates are suppressed from the detection queue.

Flows with identical **content** are deliberately **not** collapsed. Repeated identical flows are the signal an IDS exists to catch — collapsing them would hide precisely the volumetric floods and credential-stuffing loops the platform is for. Content-level aggregation belongs in a threat-aggregation component with an explicit window and counter, not in a routing node. A test pins this.

## Approval Resume

`ResponseAgent` can end a run in `AWAITING_APPROVAL`; the analyst rules later, out of band. The coordinator routes such a decision back to `ResponseAgent` **at most once per run**, recording the attempt in `resume_attempted` before dispatching. If the approval has not arrived, `ResponseAgent` returns `AWAITING_APPROVAL` again and the coordinator does not retry — so an approval that never comes cannot loop.

This required one upstream change: `ResponseAgent._next_decision_for_response` now treats `AWAITING_APPROVAL` as non-terminal, since an approved action could otherwise never execute.

## Run Summary

`metadata["coordinator_agent"]` after a run:

```json
{
  "status": "completed",
  "iteration": 20,
  "next_node": "__end__",
  "reason": "all pipeline work drained",
  "dispatches": {"detection": 5, "analysis": 5, "decision": 5, "response": 5},
  "stalled_stages": [],
  "resume_attempted": [],
  "suppressed_event_ids": [],
  "pending": {"detection": 0, "analysis": 0, "decision": 0, "response": 0, "response_resumable": 0},
  "pending_total": 0,
  "anomalies": []
}
```

`pending` counts are **absolute**, not filtered to registered stages: a partial pipeline reports the work it cannot do rather than hiding it.

## LangGraph Usage

```python
from agents.coordinator import CoordinatorAgent
from graph.builder import GraphBuilder
from graph.runtime import GraphRuntime

builder = GraphBuilder()
builder.register_node("detection", detection_agent)
builder.register_node("analysis",  analysis_agent)
builder.register_node("decision",  decision_agent)
builder.register_node("response",  response_agent)

coordinator = CoordinatorAgent()
builder.register_coordinator(
    "coordinator", coordinator, coordinator.route,
    routable_targets=coordinator.routable_targets,   # validated at build time
)

runtime = GraphRuntime(builder=builder)
```

A partial pipeline declares what it has:

```python
CoordinatorAgent(stages=["detection", "analysis"])
```

`GraphBuilder` keeps its original linear behaviour when no coordinator is registered, so existing callers and `tests/graph/test_orchestration_shell.py` are unaffected.

## Running Tests

```bash
pytest tests/agents/test_coordinator_agent.py tests/graph/test_coordinator_graph.py -v
```

## Out of Scope (This Component)

- LearningAgent
- Parallel or concurrent stage execution (routing is one node at a time)
- Content-level event aggregation
- Cross-run state rehydration and scheduling
- Priority ordering — stages drain in pipeline order, not by decision priority
