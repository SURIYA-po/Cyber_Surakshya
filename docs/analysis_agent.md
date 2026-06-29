# Analysis Agent

The Analysis Agent is the reasoning component of Cyber Surakshya. It consumes
validated platform state after detection, calls a generic AI engine, and appends
a structured `AnalysisResult`.

```text
PlatformSharedState
-> Analysis Agent
-> AIEngine
-> AnalysisResult
-> Updated Platform State
```

## Scope

This component only performs structured analysis. It does not implement:

- Coordinator Agent
- Decision Agent
- Response Agent
- Learning Agent
- MITRE ATT&CK mapping
- Threat intelligence
- LangGraph routing
- Firewall actions
- Human approval workflows
- LLM provider integrations

## AI Engine Boundary

The agent depends on the generic `AIEngine` interface:

```python
class AIEngine(Protocol):
    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        ...
```

The current implementation is `DeterministicRuleEngine`. Future engines such as
Ollama, OpenAI, Claude, Gemini, and fine-tuned cybersecurity models should
implement the same interface without changing the Analysis Agent.

AI engines are isolated from LangGraph, platform state management, threat
intelligence, decision making, and response logic.

## Input Contract

The agent is a pure LangGraph node:

```python
agent(state) -> updated_state
```

It validates `PlatformSharedState` with `PlatformStateModel`, finds the first
`DetectionResult` without a matching `AnalysisResult`, joins it to its
`SecurityEvent` by `event_id`, and builds an `AnalysisContext`.

## State Update

On success the node returns:

- one appended `AnalysisResult`
- updated `metadata["analysis_agent"]`

On failure the node returns:

- one appended error string
- updated `metadata["analysis_agent"]`

## LangGraph Usage

```python
from agents.analysis import AnalysisAgent
from ai_engine import DeterministicRuleEngine
from graph.builder import GraphBuilder
from graph.runtime import GraphRuntime

builder = GraphBuilder()
builder.register_node("analysis", AnalysisAgent(DeterministicRuleEngine()))

runtime = GraphRuntime(builder=builder)
result = runtime.execute(state_after_detection)
```
