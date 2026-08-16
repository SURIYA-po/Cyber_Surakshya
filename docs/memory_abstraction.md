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

## Query Filters

`MemoryQuery` exposes two metadata filters. Both are evaluated by
`MemoryQuery.matches_metadata()`, which every provider calls rather than
re-implementing the predicate, so the two filters cannot come to mean different
things on different backends.

### `metadata` — exact match

```python
MemoryQuery(metadata={"detection_id": "det-1", "agent": "analysis_agent"})
```

Every key must be present with exactly that value. Keys are ANDed.

### `metadata_any` — batch match

```python
MemoryQuery(metadata_any={"detection_id": ["det-1", "det-2", "det-3"]})
```

Written for joining a page of parent records to their children in **one** query
instead of one query per parent.

Contract:

- **Keys AND, values OR.** A record matches when *every* key is satisfied, and a
  key is satisfied when its value equals *any* of that key's alternatives.
- **Presence is required.** A key absent from a record's metadata never matches,
  even against a list containing `None`. This is exact matching, not a
  "missing counts as null" join.
- **An empty alternative list is rejected** at validation. It would match
  nothing, which is nearly always an accidentally-empty parent page rather than
  a deliberate request for zero rows.
- **Omitting the field changes nothing.** `metadata_any=None` leaves query
  behaviour exactly as it was.

Combining both filters ANDs them together.

### Ordering and limits

`limit` is applied **after** filtering and ordering, in every provider. A
filtered query therefore returns the newest N *matching* records — not N records
that are then filtered down to fewer. Read-model joins depend on this: a page of
children must not be silently truncated by rows that were never going to match.

Note that filtering by `metadata` / `metadata_any` / `tags` happens in Python,
after the backend's own retrieval. `QdrantSqliteMemoryProvider` pushes the
scalar filters (`record_ids`, `record_types`, `entity_ids`, `correlation_id`,
`trace_id`, and the timestamp bounds) down into SQL, but reads the candidate
rows before applying metadata predicates. Prefer a scalar filter, or bound the
query with `created_after`, when the collection is large.

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
