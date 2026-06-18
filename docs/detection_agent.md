# Detection Agent

The Detection Agent is the first actual Cyber Surakshya agent. Its only job is
to run detection for incoming platform state and append a `DetectionResult`.

```text
Flow Data
-> Detection Agent
-> IDSDetectionAdapter
-> DetectionResult
-> Updated Platform State
```

## Scope

This component only performs detection. It does not implement:

- Coordinator Agent
- Analysis Agent
- Decision Agent
- Response Agent
- Learning Agent
- MITRE ATT&CK mapping
- Threat intelligence
- LangGraph routing
- Firewall actions
- Human approval workflows
- LLM integration

## Input Contract

The agent is a pure LangGraph node:

```python
agent(state) -> updated_state
```

It accepts `PlatformSharedState`, validates it with `PlatformStateModel`, and
reads flow data from the first `SecurityEvent` that does not already have a
matching `DetectionResult`.

Flow data comes from the existing schema locations:

1. `SecurityEvent.features`
2. `SecurityEvent.raw_payload` when `features` is empty

Metadata is used only for operational status, not primary flow payloads.

## State Update

On success the node returns a LangGraph state update containing:

- one appended `DetectionResult`
- updated `metadata["detection_agent"]`

On failure the node returns:

- one appended error string
- updated `metadata["detection_agent"]`

## LangGraph Usage

```python
from agents.detection import DetectionAgent
from adapters.detection.ids_adapter import IDSDetectionAdapter
from graph.builder import GraphBuilder
from graph.runtime import GraphRuntime

builder = GraphBuilder()
builder.register_node("detection", DetectionAgent(IDSDetectionAdapter()))

runtime = GraphRuntime(builder=builder)
result = runtime.execute(initial_state)
```
