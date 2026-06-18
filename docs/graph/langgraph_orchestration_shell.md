# LangGraph Orchestration Shell

This component provides the minimal execution infrastructure that future Cyber
Surakshya agents can plug into. It contains no security logic, routing logic,
agent behavior, memory system, or workflow policy.

```text
PlatformSharedState
-> LangGraph Runtime
-> State Persistence
-> Execution Engine
```

The graph is intentionally executable as:

```text
START -> END
```

## Files

```text
graph/
  base_graph.py       # Lifecycle hooks and structured logging
  builder.py          # LangGraph initialization, node registration, compilation
  checkpointing.py    # Serialized state persistence abstraction
  config.py           # Graph runtime configuration
  runtime.py          # Execution abstraction

tests/
  graph/
    test_orchestration_shell.py
```

## State Validation

`GraphRuntime.execute()` accepts either:

- `PlatformStateModel`
- `PlatformSharedState`

The runtime validates state before execution and validates the graph output
after execution using `PlatformStateModel`.

## Persistence Contract

Persistence backends store serialized state payloads:

```python
payload = state.model_dump(mode="json")
```

They reconstruct validated state with:

```python
state = PlatformStateModel.model_validate(payload)
```

This keeps future PostgreSQL, Redis, LangGraph checkpointing, and object-storage
backends independent from live Pydantic model instances.

## Node Registration

Future components can register graph nodes through `GraphBuilder.register_node`.
The current shell chains registered nodes linearly in registration order. It
does not define routing or security decisions.
