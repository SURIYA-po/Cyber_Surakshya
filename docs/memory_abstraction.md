# Memory Abstraction Layer

The Memory Abstraction Layer defines the storage contract used by future
platform components. It is not a vector database, RAG system, embedding store,
or external database implementation.

```text
Platform component
-> MemoryProvider
-> concrete backend adapter
```

## Scope

This component provides:

- generic memory models
- a `MemoryProvider` interface
- a thread-safe `InMemoryMemoryProvider`
- collection-scoped CRUD and search

It does not implement embeddings, vector search, semantic search, LLM memory,
RAG, Redis, PostgreSQL, ChromaDB, FAISS, Milvus, Qdrant, or Elasticsearch.

## Collections

Every operation is scoped to a collection:

```python
provider.store("security_events", record)
provider.search("analysis", query)
provider.get("detections", record_id)
```

Collection names are generic strings. Examples include:

- `security_events`
- `detections`
- `analysis`
- `incidents`
- `learning`
- `conversations`
- `custom`

The provider does not hardcode cybersecurity concepts.

## Record Shape

`MemoryRecord` stores generic references instead of importing domain schemas:

- `backend`
- `collection`
- `record_type`
- `entity_id`
- `correlation_id`
- `trace_id`
- `metadata`
- `tags`
- `content`

This allows records to reference `SecurityEvent`, `DetectionResult`, or
`AnalysisResult` by identifier without coupling the memory layer to those
models.

## Dependency Inversion

Agents and services should depend on `MemoryProvider`, not a concrete backend.
The current in-memory adapter can be replaced by future providers without
changing agent code.

## Future Backends

Future adapters can implement the same interface:

- `PostgreSQLMemoryProvider`
- `RedisMemoryProvider`
- `ChromaMemoryProvider`
- `FAISMMemoryProvider`
- `QdrantMemoryProvider`
- `ElasticsearchMemoryProvider`

Vector-capable backends may store extra backend-specific data internally, but
the platform-facing contract remains `MemoryProvider`.
