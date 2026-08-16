# Cyber Surakshya — Codebase Assessment

**Date:** 2026-08-02 (findings) · **Updated:** 2026-08-03 (remediation)
**Branch:** `surya`  ·  **Reviewer role:** Senior developer / IT architect

> ## Remediation status
>
> All **Critical (§4.1)** and **Important (§4.2)** items are now **done**.
> Test suite: **426 passing, 0 errors** (was 416 passing, 15 errors).
>
> | | Item | Status |
> |---|---|---|
> | C1 | Fail closed on missing artifacts; `/health` proves the detector | ✅ |
> | C2 | `requirements.txt` completed (qdrant-client, sentence-transformers, scapy) | ✅ |
> | C3 | `cicflowmeter` gitlink → vendored files; **+15 untracked `__init__.py` recovered** | ✅ |
> | C4 | API key moved to `CYBER_SURAKSHYA_API_KEY` / `VITE_API_KEY` | ✅ |
> | C5 | `evaluation_report.txt` annotated; `train.py` now emits macro metrics | ✅ |
> | C6 | Risk scoring: per-class base severity replaces `confidence × 100` | ✅ |
> | C7 | Legacy CSV path handles cicflowmeter snake_case + seconds→µs | ✅ |
> | C8 | `OVERVIEW.md` / `GUIDEBOOK.md` corrected | ✅ |
> | I1 | Anomaly layer wired into the agent path | ✅ |
> | I2 | `/feed` streams real log events (`observability/`) | ✅ |
> | I3 | 15 Windows teardown errors fixed (connection leak) | ✅ |
> | I4 | `app.py` 1,646 → **112 lines**; 8 routers + lifespan | ✅ |
> | I5 | `MOCK_*` globals removed; `DELETE /alerts` really deletes | ✅ |
> | I6 | Triple-nested comprehension replaced | ✅ |
> | I7 | End-to-end pcap→detection test added | ✅ |
> | I8 | ~800 lines of dead code deleted | ✅ |
> | I9 | Derived/sensitive data gitignored | ✅ |
> | I10 | `predict_supervised` / `predict_dual_layer` split | ✅ |
>
> Three bugs were found *during* remediation that this report had missed:
> the `__init__.py` gitignore entry (C3), the agent `_error_update` crash, and
> a Unicode print that disabled the anomaly layer's status on Windows.
>
> **Nice-to-have tier (§4.3), in progress — 446 tests passing:**
>
> | | Item | Status |
> |---|---|---|
> | N5 | Reproducibility manifest written by `train.py` | ✅ |
> | N7 | `artifacts/manifest.json` model registry; `resolve_model_path` honours it | ✅ |
> | N6 | `ruff` configured and clean (`pyproject.toml`) | ✅ |
> | N8 | `/metrics` Prometheus endpoint over existing counters | ✅ |
> | N1 | Improve BOTNET recall / add INFILTRATION | ⬜ research task |
> | N2 | Give `AnalysisAgent` real signal (MITRE mapping, enrichment) | ⬜ |
> | N3 | LLM decision engine | ⬜ **provider decided: Ollama (local)** |
> | N4 | Real response executor | ⬜ needs backend choice |
>
> **N3 — decided 2026-08-03: Ollama, local.** Flow records inside a prompt are
> network telemetry; keeping inference on-host means they never leave the
> machine. Implement as `OllamaDecisionEngine` against the existing
> `DecisionEngine` protocol in `agents/decision/base.py`, then uncomment the
> `OllamaDecisionEngine: AI_SUPERVISED` line already waiting in
> `config/response_policy.yaml` — that tier caps a language model at
> non-destructive actions behind a 0.90 confidence floor, the right default
> for a first LLM integration.
>
> **N4 note:** this project runs on Windows, so the natural first target is
> Windows Firewall (`netsh advfirewall`) rather than nftables/iptables —
> unless it deploys to Linux, which is what `docker/` already assumes for
> capture.
>
> **A fourth missed bug surfaced during N7:** `train.py` selected the model to
> save as `model.pkl` by **weighted** F1 — the exact metric that cannot
> distinguish the served DNN (0.95 WEBATTACK recall) from three models at
> 0.08–0.10. Selection is now macro F1 with a per-class recall floor
> (`MIN_CLASS_RECALL = 0.50`), and all three weak models are explicitly
> rejected.

**Scope:** All first-party modules (~12,000 lines of Python, ~40 React files), the ML artifacts, the test suite, and the deployment configuration. Third-party code in `.venv/` and the vendored `cicflowmeter/` package were inspected only where they affect correctness.

---

## Glossary (terms used throughout)

| Term | Plain-language meaning |
|---|---|
| **IDS** | Intrusion Detection System — software that watches network traffic and flags attacks. |
| **Flow** | One conversation between two computers (source IP/port → destination IP/port), summarised as ~80 numbers (duration, packet counts, byte counts, timing). The model never sees raw packets, only these summaries. |
| **CICIDS2017** | A public, labelled dataset of network flows containing normal traffic plus seven attack families. The model was trained on it. |
| **CICFlowMeter** | The tool that turns raw captured packets into flow summaries. There is a Java original and a Python re-implementation; they use *different column names and different time units*. This distinction causes a major bug described below. |
| **Agent** | A Python class that does one job in the pipeline and hands its result to the next. Here: detection, analysis, decision, response, learning, coordination. |
| **LangGraph** | A library for wiring agents together as a graph, where a "coordinator" node decides who runs next. |
| **Adapter** | A translation layer that lets the clean agent code talk to messy external code (the ML model, a firewall) without depending on it directly. |
| **Guard / blast radius** | Safety rules that limit what automated containment is allowed to do (e.g. never block the loopback address, never block more than 3 IPs per incident). |
| **Fail-open / fail-closed** | Fail-open = when something breaks, the system keeps running but stops protecting (dangerous). Fail-closed = when something breaks, the system refuses to act (safe). |
| **Zero-fill** | When a required input number is missing, substituting `0`. Sounds harmless; for an ML model it produces a *confident wrong answer*. |

---

## 1. Project Status Overview

### 1.1 What this project is

Cyber Surakshya is an AI-driven network security platform. It has two halves that were built at different times and to noticeably different standards:

**Half A — the classical ML core (older, prototype quality).**
`preprocess.py` → `train.py` → `artifacts/*.pkl` → `inference.py`. Trains a multi-class classifier on CICIDS2017 to label a flow as `BENIGN` or one of six attack families, plus an unsupervised "anomaly layer" (Isolation Forest + a hand-rolled NumPy autoencoder) intended to catch things the classifier has never seen.

**Half B — the agentic platform (newer, production quality).**
A strictly-layered multi-agent system:

```
capture (dumpcap) → pcap files → cicflowmeter → FlowNormalizer → Redis Stream
                                                                       │
                                                                       ▼
                                                              PipelineBridge
                                                                       │
                                       ┌───────────────────────────────┘
                                       ▼
                            CoordinatorAgent (hub)
                          ╱        │         │        ╲
                 DetectionAgent  Analysis  Decision  ResponseAgent
                        │        Agent     Agent          │
                        ▼                                 ▼
                IDSDetectionAdapter              ExecutorRegistry
                        │                          (simulated only)
                        ▼
                   inference.py  ← Half A

        LearningAgent (runs over history, NOT in the pipeline)
        FastAPI (app.py) → React dashboard (frontend/)
```

### 1.2 Overall maturity

| Signal | Reading |
|---|---|
| Test suite | **416 passing, 15 errors** (`pytest`, 3m40s). All 15 errors are one Windows-specific issue, not logic failures — see §2.4. |
| Test-to-code ratio | Roughly 1:1 for the newer layers (ingestion has 2,100 lines of tests for 2,400 lines of code). Near zero for `train.py`, `preprocess.py`, `app.py`. |
| Architectural discipline | Excellent in `agents/`, `adapters/`, `graph/`, `ingestion/`, `cyber_surakshya/platform/`. Every module has a documented "DOES / DOES NOT" boundary that is actually respected. |
| Technical debt concentration | Almost entirely in **`app.py` (1,536 lines)**, **`inference.py` (1,000+ lines)**, and the artifact/training scripts. |
| Documentation | Unusually good (`docs/` has per-agent design docs and implementation plans), but **`OVERVIEW.md` and `GUIDEBOOK.md` are now factually wrong in several places** (§3.2). |

**Verdict:** this is a strong final-year/research platform that is roughly **80% of the way to a coherent whole**. The remaining 20% is not "more features" — it is *reconciling the older ML half with the newer agentic half*, which currently disagree with each other in ways that silently produce wrong security outcomes.

### 1.3 Module completeness

| Module | Path | Status | Notes |
|---|---|---|---|
| Platform schemas & enums | `cyber_surakshya/platform/` | ✅ **Complete** | Pydantic v2, `extra="forbid"`, well tested. The strongest foundation in the repo. |
| Memory abstraction | `memory/` | 🟡 **Complete but over-supplied** | Three backends; only one is used. See §2.1. |
| LangGraph shell | `graph/` | ✅ **Complete** | Small, clean, supports both linear and coordinated modes. |
| Detection adapter | `adapters/detection/` | 🟠 **Works, but semantically wrong** | See §3. |
| DetectionAgent | `agents/detection/` | ✅ **Complete** | |
| AnalysisAgent + rule engine | `agents/analysis/`, `ai_engine/` | 🟡 **Complete but near-empty** | The "analysis" restates the detection in prose; it adds no new signal. See §2.2. |
| DecisionAgent + policy | `agents/decision/` | ✅ **Complete** | 6-rule ordered policy table, clean design. Thresholds are miscalibrated — §3.6. |
| ResponseAgent + guard | `agents/response/` | ✅ **Complete** (simulated only) | 1,600 lines. Genuinely production-grade authorisation logic. No real firewall/EDR integration exists. |
| Response executors | `adapters/response/` | 🟡 **Simulated only** | `SimulatedContainmentExecutor`, `NotificationExecutor`. Deliberate and documented. |
| CoordinatorAgent | `agents/coordinator/` | ✅ **Complete** | Stall detection, iteration budget, work queue. Well designed. |
| LearningAgent (5 sub-modules) | `agents/learning/` | ✅ **Complete** | 1,900 lines. Advisory only — never retrains. |
| Live ingestion | `ingestion/` | ✅ **Complete, untested end-to-end** | 2,400 lines, excellent. Never demonstrated running against a live NIC in this repo's evidence. |
| ML training | `train.py`, `preprocess.py` | 🟠 **Complete but unversioned/untested** | No tests, no seed-locked reproducibility record, artifacts hand-edited. |
| Inference | `inference.py` | 🔴 **Partly broken** | See §3.3, §3.4. |
| FastAPI backend | `app.py` | 🟠 **Works, but is a monolith** | See §2.3. |
| React frontend | `frontend/src/` | 🟡 **Complete pages, partly fake data** | 12 routes wired; `/feed` is theatre (§2.5); mock constants are dead code. |
| Docker / Redis hardening | `docker/`, `docker-compose.yml` | ✅ **Complete** | Non-root, cap-dropped, read-only, loopback-bound, ACL users. Genuinely good. |

---

## 2. Complexity and Integration Issues

### 2.1 Over-engineered / unnecessarily complex

**(a) Three memory backends, one used.**
`memory/` ships `InMemoryMemoryProvider` (219 lines), `QdrantSqliteMemoryProvider` (369 lines), and `PostgreSQLMemoryProvider` (430 lines). Only the Qdrant+SQLite one is used by `app.py`; the in-memory one is used by tests; **`memory/postgresql.py` is used by nothing at all** — no import outside its own file, no test file. That is 430 lines of async SQL that has never executed.
*Recommendation:* delete `memory/postgresql.py` or move it to a `contrib/` folder. It is a maintenance liability that looks like a supported feature.

**(b) The `_load_frontend_state_from_memory` comprehension.**
[app.py:578-606](app.py#L578-L606) is a **triple-nested list comprehension that rebuilds the same dictionary three times** and then filters it. All three passes are identity transforms of each other. It can be replaced by one 8-line loop with no change in behaviour. This is the single worst-readability block in the repo.

**(c) `inference.predict()` has two incompatible calling conventions.**
[inference.py:433-465](inference.py#L433-L465) accepts *either* `predict(df, artifacts_container)` *or* `predict(df, model, scaler, le, feature_cols)`, and disambiguates with `isinstance(scaler, bool)` checks. This dual signature is what silently disables the anomaly layer for the entire agent pipeline (§3.4). Two clearly-named functions would remove an entire class of bug.

**(d) `IDSArtifacts` vs `adapters/detection/ids_adapter.IDSArtifacts`.**
Two different classes with the same name, in two modules, holding overlapping data. Confusing on sight.

**(e) `CICFLOW_ALIASES` (88 entries) is largely dead.**
[inference.py:104-191](inference.py#L104-L191) maps Java-CICFlowMeter and CICIDS2017 spellings. Roughly 40 of its entries are identity mappings (`"Flow Bytes/s" → "Flow Bytes/s"`) that do nothing, and none of it matches the Python cicflowmeter actually used by the ingestion layer. It creates the *impression* of a solved naming problem that is in fact solved elsewhere (`ingestion/flows/normalizer.py`).

*Not over-engineered, despite appearances:* `agents/response/guard.py` (566 lines) and `agents/coordinator/routing.py` (354 lines) look heavy but every branch corresponds to a real failure mode documented in the code. Leave them alone.

### 2.2 Built but not fully integrated

| Feature | Built in | Why it isn't really integrated |
|---|---|---|
| **Anomaly layer (Isolation Forest + autoencoder)** | `train.py`, `artifacts/iforest.pkl`, `artifacts/autoencoder.pkl` | **Never runs in the agent pipeline.** `IDSDetectionAdapter` calls `inference.predict` with the 5-positional-argument form, which hard-codes `anomaly_ready = False`. The two model files are loaded into memory at startup and then ignored. §3.4. |
| **`DetectionResult.is_anomaly`** | `cyber_surakshya/platform/schemas/detection_result.py` | Set to `status == DETECTED` — i.e. it is a synonym for "the classifier said attack", not an anomaly signal. Any downstream consumer reading it as "unsupervised anomaly detected" is misled. |
| **`inference.predict`'s `final_status` column** | [inference.py:498-514](inference.py#L498-L514) | Computed on every call, then discarded — the adapter recomputes its own status with `_status_for()`. Two copies of the same rule, one dead. |
| **Zeek `conn.log` translation** | [inference.py:547-705](inference.py#L547-L705), ~160 lines | Only reachable through the `/predict/zeek` and `/simulation/upload-zeek` endpoints. The live pipeline uses cicflowmeter, not Zeek. This is a parallel, unmaintained ingestion path. |
| **Live ingestion layer** | `ingestion/` (2,400 lines) | Fully built, well tested with `fakeredis`, wired to `/ingestion/*` endpoints and a `LiveCapture.jsx` page. But nothing in the repo shows it having produced a single real detection — `predictions.csv` (§3.3) was produced by the *legacy* CSV path, and produced 5,155 `BENIGN` rows out of 5,155. |
| **`memory/postgresql.py`** | 430 lines | Zero call sites. |
| **`frontend/src/constants/*.js`** | 379 lines of mock alerts/dashboards | Zero imports. Dead code left from the pre-API scaffold. |
| **`MOCK_ALERTS` / `MOCK_ANALYSES` / `MOCK_BLOCKED_IPS`** | `app.py` | Half-migrated. `/alerts` reads from memory but falls back to these lists; `DELETE /alerts/{id}` ([app.py:640-644](app.py#L640-L644)) *only* mutates `MOCK_ALERTS`, so deleting an alert from the UI does nothing once real detections exist. |

### 2.3 `app.py` — the main structural problem

1,536 lines, 63 KB, one file. It contains: dependency wiring, authentication, 45+ endpoints across 8 domains, an SSE generator, six hardcoded attack profiles, Zeek CSV upload handling, and several private helper functions. Specific issues:

- **Hardcoded API key in source.** [app.py:98](app.py#L98): `if api_key != "cyber-surakshya-secret-key"`. The same literal is hardcoded in [frontend/src/api/axios.js](frontend/src/api/axios.js). This must come from the environment.
- **`ensure_runtime()` swallows every exception.** [app.py:238-239](app.py#L238-L239) catches `Exception`, prints, and returns `None`. A model that failed to load looks identical to a healthy start except for one line of stdout.
- **`@app.on_event("startup")` is deprecated** in modern FastAPI; use a lifespan context manager.
- **Module-level `ensure_runtime()` at import time** ([app.py:243](app.py#L243)) makes the module un-importable for testing without loading ~100 MB of models and a sentence-transformer.
- **`datetime.utcnow()`** used in several places — deprecated in Python 3.12+, and produces naive datetimes in a codebase that is otherwise rigorous about UTC-aware timestamps.
- No routers, no dependency-injection container, no request/response models for most endpoints.

### 2.4 Incomplete / broken items

| Item | Detail |
|---|---|
| **15 test errors** | `tests/memory/test_qdrant_sqlite.py` — all 15 are `PermissionError: [WinError 32]` in **teardown**: the SQLite connection is still open when `TemporaryDirectory` tries to delete the file. Windows-only. The tests themselves pass; the fixture leaks a handle. Fix: close the provider in the fixture (add a `close()`/context-manager to `QdrantSqliteMemoryProvider`). |
| **`requirements.txt` is incomplete** | `qdrant_client`, `sentence_transformers`, `asyncpg`, and `scapy`/`cicflowmeter` are imported by production code but absent from `requirements.txt`. A fresh `pip install -r requirements.txt && uvicorn app:app` **crashes at import** (`app.py:77` → `memory.qdrant_sqlite` → `qdrant_client`). |
| **`cicflowmeter/` is a broken gitlink** | `git ls-files -s cicflowmeter` shows mode `160000` (a submodule pointer to commit `5916fdd9`), but **there is no `.gitmodules` file**, and `.gitignore` now contains `cicflowmeter/*`. A fresh clone gets an empty directory and no way to populate it — the ingestion layer will not import. Must be resolved: either add `.gitmodules` properly, or vendor the source as normal tracked files. |
| **Large binaries in the working tree** | `artifacts/model_VotingEnsemble.pkl` (102 MB), `model_RandomForest.pkl` (42 MB), `malware_c2.pcap` (3.6 MB), `out.csv`/`predictions.csv` (2.3/2.6 MB), `memory_metadata.db` (1 MB) sit untracked or tracked at the repo root. The `.pcap` is now gitignored (correct — it is a record of who talked to whom), but `out.csv` and `predictions.csv` are derived from it and are **not** ignored. |
| **`.env` is committed-adjacent** | `.env` exists alongside `.env.example` with identical size (1,704 bytes). `.env` is gitignored — verify it never entered history. |
| **Dead endpoints** | `DELETE /alerts/{id}` and `DELETE /blocked/{id}` operate on the mock lists only. |

### 2.5 The `/feed` endpoint is fabricated

[app.py:250-308](app.py#L250-L308) is a Server-Sent Events stream that the dashboard renders as live agent activity. It emits **randomly chosen strings** from a hardcoded list whenever an alert was created in the last 15 seconds:

```python
"Applying VotingEnsemble / Random Forest model...",
"Evaluating anomaly layer (Isolation Forest + Autoencoder)...",
"Cross-referencing IOCs...",
"Updating behavioral baseline...",
```

None of these correspond to anything happening. Two of them describe capabilities the platform **does not have** — the anomaly layer never runs in the pipeline (§3.4), and there is no IOC cross-referencing or behavioural baseline anywhere in the codebase. Real structured logs already exist (`detection_agent_started`, `bridge_batch_completed`, `ingestion_retention_swept`); the feed should stream those.

This matters beyond cosmetics: a demo of this dashboard shows a reviewer capabilities that are not implemented.

---

## 3. Detection Layer / ML Model Deep Dive

### 3.1 Role and data path

The detection layer is the **entry point of the entire agentic pipeline**. Everything downstream — analysis, decision, containment, learning — is a transformation of `DetectionResult`. If detection is wrong, nothing later can recover, because no other component looks at the raw flow.

The full path for a live flow:

```
packet capture (dumpcap, snaplen 96 — headers only)
    → pcap file (closed, rotated every 60s)
    → cicflowmeter → CSV with snake_case columns, SECONDS time base
    → FlowNormalizer          ← renames to CICIDS Title Case, ×1e6 on time features
    → Redis Stream
    → EventBuilder → SecurityEvent(features={...})
    → DetectionAgent._extract_flow_data()
    → IDSDetectionAdapter.detect()
    → inference.predict()
        → preprocess_for_inference()  ← aligns to 42 columns, ZERO-FILLS missing, scales
        → model.predict() / predict_proba()
    → DetectionResult(status, confidence, risk_score, severity, probabilities)
```

### 3.2 Does the model detect the intended attack types?

**Partly, and the documentation overstates it.**

The label encoder holds **7 classes**, not 8:

```
BENIGN, BOTNET, BRUTEFORCE, DDOS, DOS, PORTSCAN, WEBATTACK
```

`GUIDEBOOK.md` and `OVERVIEW.md` both claim **8 classes including `INFILTRATION`**. `INFILTRATION` is absent from `preprocess.py:CLASS_ORDER`, absent from `LABEL_MAP`, and absent from the trained encoder — even though `data/raw/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` is present. **The platform cannot detect infiltration/lateral-movement at all.** The docs must be corrected.

Per-class **recall** from `artifacts/evaluation_report.txt`:

| Class | **DNN (served)** | RandomForest | GradientBoosting | VotingEnsemble |
|---|---|---|---|---|
| BENIGN | 1.00 | 1.00 | 1.00 | 1.00 |
| DDOS | 1.00 | 1.00 | 1.00 | 1.00 |
| DOS | 1.00 | 1.00 | 1.00 | 1.00 |
| PORTSCAN | 1.00 | 1.00 | 1.00 | 1.00 |
| BRUTEFORCE | 0.99 | 1.00 | 1.00 | 1.00 |
| **BOTNET** | **0.74** | 0.61 | 0.61 | 0.61 |
| **WEBATTACK** | **0.95** | **0.08** | **0.10** | **0.10** |
| INFILTRATION | — not modelled (no rows in the cleaned dataset) — | | | |
| **Macro F1** | **0.97** | 0.84 | 0.84 | 0.85 |

> **Correction (2026-08-03).** An earlier revision of this document reported macro F1 0.84 and WEBATTACK recall 0.08 as the platform's headline figures. Those belong to RandomForest and GradientBoosting, which are **trained and saved but never served**. `inference.resolve_model_path` selects `model_DNN.pkl` (no `model.pkl` exists), and the loaded estimator is confirmed to be `MLPClassifier`. The served model's macro F1 is **0.97** with WEBATTACK recall **0.95**.

**"99.4% accuracy" is still the wrong headline** — weighted metrics are dominated by the four high-volume classes — but the correct headline for the served model is macro F1 **0.97**, which is genuinely strong.

Two real caveats remain:

* **BOTNET recall 0.74** — roughly one in four C2 flows is missed, and C2 implies an already-compromised host.
* **No INFILTRATION class at all.** The cleaned dataset contains zero infiltration rows, so lateral movement is undetectable regardless of model quality.

**Model-selection hazard:** the three non-served models collapse on WEBATTACK (0.08–0.10 recall). `resolve_model_path`'s preference list is what keeps the good model in production, and `model_VotingEnsemble.pkl` (102 MB, the most impressive-sounding artifact) is one of the weak ones. Writing a `model.pkl` from any of them would silently degrade detection.

### 3.3 Is it compatible with the system's data formats?

**Two ingress paths, and only one of them works.**

**Path A — the live ingestion layer: CORRECT.**
`ingestion/flows/normalizer.py` is the best-reasoned file in the repository. Its module docstring identifies and fixes two silent mismatches:
1. **Naming** — cicflowmeter emits `flow_duration`; the model wants `Flow Duration`. `FEATURE_SOURCE_MAP` maps all 42 explicitly.
2. **Units** — cicflowmeter emits **seconds**; CICIDS2017 is **microseconds**. `MICROSECOND_FEATURES` enumerates the 13 affected columns and multiplies by 1e6. The rate columns (`Flow Bytes/s` etc.) are listed separately in `RATE_FEATURES` specifically so a test can assert they are *never* scaled.

It is also **strict by default**: a missing column raises `FeatureContractError` rather than zero-filling. That is the right call, and it is explained in the code.

**Path B — the legacy `inference.py` CSV/JSON path: SILENTLY BROKEN.**
`preprocess_for_inference()` matches columns **by name** after applying `CICFLOW_ALIASES`, which only knows Java-CICFlowMeter spellings. Given Python-cicflowmeter output, **zero of 42 features match**, and every one is zero-filled.

This is not theoretical. `predictions.csv` in the repo root is `out.csv` (5,155 real captured flows) scored through this path:

```
prediction     : BENIGN × 5155  (100%)
final_status   : BENIGN × 5155  (100%)
confidence     : mean 1.0, std 0.0, min 1.0, max 1.0
is_anomaly     : False × 5155
```

Every flow, maximum confidence, zero variance. That is the signature of a constant input vector, not of benign traffic. **A user running `python inference.py --csv out.csv` gets a detector that cannot say anything but "safe".**

**The `pyDestination Port` artifact bug (already fixed — verified correct).**
`artifacts/feature_columns.json` contained `"pyDestination Port"` at index 25, a stray `py` typed into the JSON. It was corrected to `"Destination Port"` in the working tree. I verified this is the right fix rather than a hazard: the `StandardScaler` is positional (`n_features_in_=42`, `feature_names_in_=None`), and the fitted statistics at index 25 are `mean=4306.3, scale=12838.7` — a destination-port distribution, not a garbage column. Training was unaffected; only name-based lookup broke, which is exactly the live path. **This fix is correct and must be committed.** (`artifacts/evaluation_report.txt:116` still shows the typo and should be regenerated or annotated.)

### 3.4 The anomaly layer does not run in the pipeline

`train.py` trains an Isolation Forest and a NumPy autoencoder; `artifacts/iforest.pkl` (1.4 MB) and `artifacts/autoencoder.pkl` are loaded at startup by `IDSArtifacts`. But:

[adapters/detection/ids_adapter.py:85-92](adapters/detection/ids_adapter.py#L85-L92) calls

```python
inference.predict(raw_df, artifacts.model, artifacts.scaler,
                  artifacts.label_encoder, artifacts.feature_columns,
                  return_proba=True)
```

which takes the **5-argument branch** at [inference.py:445-453](inference.py#L445-L453), where `anomaly_ready = False` is hard-coded. The anomaly layer is therefore skipped for **every detection the platform makes**. It only runs via the CLI/`predict_csv` path — which is itself broken (§3.3).

Consequences:
- The "dual-layer detection" claimed in `OVERVIEW.md` does not exist at runtime.
- `DetectionStatus.INCONCLUSIVE` can only ever be produced by the low-confidence branch, never by the "classifier says benign but anomaly fired" branch.
- `DecisionEngine` Rule 5's rationale — *"Anomaly signal is present but the supervised classifier is uncertain"* — is **factually false** whenever it fires.
- Any novel attack (anything unlike the seven trained classes) is classified into the nearest known class with high confidence, with no second opinion.

### 3.5 Fail-open on missing artifacts

[inference.py:261-272](inference.py#L261-L272): if the model file is absent, `IDSArtifacts` substitutes `_FallbackModel` (returns class 0 for everything), `_FallbackScaler` (identity), and `_FallbackLE` (`classes_ = ["BENIGN"]`). `_FallbackModel.predict_proba` returns `ones((n, 1))` → confidence 1.0.

So a deployment with a missing or corrupt model artifact reports **"BENIGN at 100% confidence"** for all traffic — and `GET /health` ([app.py:311-314](app.py#L311-L314)) returns `{"status": "ok", "artifacts_loaded": true}`, because it only checks `RUNTIME is not None`.

**A security product that silently degrades to "everything is fine" is worse than one that crashes.** This is the single most important correctness issue in the detection layer.

### 3.6 Risk scoring collapses attack severity into model confidence

[adapters/detection/ids_adapter.py:208-223](adapters/detection/ids_adapter.py#L208-L223):

```python
risk = round(confidence * 100.0, 4)      # for any non-benign label
```

Risk is **purely a function of classifier confidence**. Attack type is not considered. Combined with a model that is 99%+ confident on its easy classes, this produces a damaging cascade:

| Step | Result |
|---|---|
| Model classifies a PORTSCAN at 0.99 confidence | |
| `risk = 99.0` | → `RiskLevel.CRITICAL` (band ≥ 80) |
| `severity_from_risk_score(99)` | → `Severity.CRITICAL` |
| `DeterministicDecisionEngine` Rule 1: `min_severity=CRITICAL, min_risk=80` | → **`BLOCK_IP`, `requires_approval=False`, `AUTO_APPROVED`** |

A routine port scan and a volumetric DDoS both produce an **unapproved automatic IP block**. The `ActionGuard`'s blast-radius limits (max 3 destructive actions per correlation, 10/minute globally) are the only thing standing between this and a self-inflicted outage — and they are limits, not corrections.

Risk should be a function of *(attack class base severity) × (confidence) × (asset criticality)*, not confidence alone. A per-class severity weight table is a ~20-line change with large operational impact.

### 3.7 Inconsistent handling of missing features

The two ingress paths disagree on a safety-critical question:

| Path | Missing feature behaviour |
|---|---|
| `ingestion/flows/normalizer.py` (strict=True) | **Raises `FeatureContractError`** — documented rationale: *"a fabricated feature yields a confident wrong detection that nothing downstream can catch."* |
| `inference.preprocess_for_inference()` | **Zero-fills silently.** |

The simulation endpoint takes the second path. `ATTACK_PROFILES` ([app.py:1205-1284](app.py#L1205-L1284)) supplies between 16 and 55 features per profile; the model needs 42 specific ones. `PortScan`, `Botnet_C2`, `DoS_Hulk` and `Normal_HTTP_GET` each omit 20+ required features (all `Idle *`, `Bwd IAT Max`, `min_seg_size_forward`, `Init_Win_bytes_backward`, …) which are zero-filled. **The demo the project is shown with runs the model on a partly-fabricated input vector.** `PortScan` also sets `"Destination Port": 0`, which is not a valid port.

### 3.8 Maintainability of the ML half

- **No tests.** `train.py` (760 lines) and `preprocess.py` (600 lines) have zero test coverage. `tests/test_inference_artifacts.py` is 15 lines.
- **No reproducibility record.** No record of which dataset revision, sample cap, feature-selection seed, or hyperparameters produced the committed artifacts. `data/cicids2017_cleaned.csv` (717 MB) is gitignored, so the artifacts cannot be regenerated from the repository.
- **Fragile pickle compatibility.** [inference.py:64-76](inference.py#L64-L76) injects `train.NumpyAutoencoder` into `sys.modules["__main__"]` so old pickles unpickle. This works but means the autoencoder artifact is tied to `train.py`'s current class definition. A `joblib`-friendly module-level class or an explicit `.npz` weight format would be safer.
- **Model selection is implicit.** `resolve_model_path` ([inference.py:198-225](inference.py#L198-L225)) picks the first existing file from a hardcoded preference list (`model.pkl`, then `model_DNN.pkl`, …). In practice `model_DNN.pkl` is selected, which happens to be the best model — but by coincidence of list order, not by reading the evaluation report. The 102 MB `model_VotingEnsemble.pkl` is never used.

### 3.9 What needs to change in the detection layer — summary

| # | Change | Why |
|---|---|---|
| D1 | Make missing artifacts **fail closed**: raise instead of substituting `_FallbackModel`; make `/health` verify a real prediction round-trip. | Removes the silent "everything is BENIGN" failure mode. |
| D2 | Route the anomaly layer into the agent path: have `IDSDetectionAdapter` pass the `IDSArtifacts` container (single-argument form), and map the result to `DetectionResult.is_anomaly` / `INCONCLUSIVE`. | Delivers the dual-layer detection already trained and already documented. |
| D3 | Replace `risk = confidence × 100` with a per-class base-severity table modulated by confidence. | Stops routine port scans triggering unapproved auto-blocks. |
| D4 | Route the legacy CSV/JSON path through `FlowNormalizer` instead of `CICFLOW_ALIASES`, or delete the legacy path. | Ends the 100%-BENIGN silent failure demonstrated by `predictions.csv`. |
| D5 | Make `preprocess_for_inference` refuse (or loudly warn on) inputs where >20% of features are zero-filled. | Aligns the two ingress paths on the same safety rule. |
| D6 | Correct `OVERVIEW.md`/`GUIDEBOOK.md`: 7 classes, no INFILTRATION; report macro-F1 (0.97 served) alongside accuracy 0.997. | The current claims are not true. |
| D7 | Pin the served model explicitly rather than relying on `resolve_model_path`'s list order; improve BOTNET recall (0.74) and add `INFILTRATION` from `data/raw/`. | The three non-served models have 0.08–0.10 WEBATTACK recall; nothing prevents one being promoted. |
| D8 | Commit `artifacts/feature_columns.json` (the `pyDestination Port` fix) and regenerate `evaluation_report.txt`. | Verified correct; currently uncommitted. |
| D9 | Fix `ATTACK_PROFILES` to supply all 42 features, and drop `"Destination Port": 0`. | The demo currently scores fabricated vectors. |
| D10 | Add a reproducibility manifest (dataset hash, seed, params, sklearn version) written by `train.py` next to the artifacts. | Artifacts are currently unreproducible. |

---

## 4. Remaining Tasks and Recommendations

### 4.1 Critical — the system is wrong or unshippable without these

| # | Task | Files | Effort |
|---|---|---|---|
| C1 | **Fail closed on missing/corrupt model artifacts**; make `/health` do a real prediction. | `inference.py:261-272`, `app.py:311` | S |
| C2 | **Fix `requirements.txt`** — add `qdrant-client`, `sentence-transformers`, `scapy`, and pin them. Move `asyncpg` to an extra or delete `memory/postgresql.py`. A clean install currently cannot start the app. | `requirements.txt` | S |
| C3 | **Fix the `cicflowmeter` gitlink** — add `.gitmodules`, or vendor the source as tracked files and remove `cicflowmeter/*` from `.gitignore`. A fresh clone cannot run ingestion. | `.gitmodules`, `.gitignore` | S |
| C4 | **Move the API key to the environment** and out of both `app.py:98` and `frontend/src/api/axios.js`. | `app.py`, `frontend/` | S |
| C5 | **Commit the `feature_columns.json` fix** and regenerate `evaluation_report.txt`. | `artifacts/` | S |
| C6 | **Fix the risk-scoring cascade** (D3) so `BLOCK_IP` without approval is not the default outcome for every confident detection. | `adapters/detection/ids_adapter.py:208`, `agents/decision/deterministic.py:58` | M |
| C7 | **Fix or delete the legacy CSV inference path** (D4). Right now it returns 100% BENIGN on real capture data. | `inference.py:386-426` | M |
| C8 | **Correct the documentation** (D6) — 7 classes, no INFILTRATION, report macro-F1, name the served model. | `OVERVIEW.md`, `GUIDEBOOK.md` | S |

### 4.2 Important — needed for the system to be coherent and credible

| # | Task | Files | Effort |
|---|---|---|---|
| I1 | **Wire the anomaly layer into the pipeline** (D2). | `adapters/detection/ids_adapter.py`, `inference.py` | M |
| I2 | **Replace the fake `/feed`** with a real log stream (structured events already exist). | `app.py:250-308` | M |
| I3 | **Fix the 15 Windows test errors** — give `QdrantSqliteMemoryProvider` a `close()` and use it in the fixture. | `memory/qdrant_sqlite.py`, `tests/memory/test_qdrant_sqlite.py` | S |
| I4 | **Split `app.py` into routers** — `routes/alerts.py`, `routes/response.py`, `routes/learning.py`, `routes/ingestion.py`, `routes/simulation.py` + a `dependencies.py` holding what `ensure_runtime()` builds. Replace `@app.on_event` with a lifespan handler. | `app.py` | L |
| I5 | **Finish the mock-state migration** — make `DELETE /alerts` and `DELETE /blocked` operate on memory; delete `MOCK_*` globals and `frontend/src/constants/*.js`. | `app.py`, `frontend/` | M |
| I6 | **Simplify `_load_frontend_state_from_memory`** (§2.1b) — one loop instead of three nested comprehensions. | `app.py:551-610` | S |
| I7 | **Add an end-to-end ingestion test** that runs a small pcap through capture→cicflowmeter→normalizer→bridge→pipeline and asserts a non-trivial detection. This is the one guarantee the excellent ingestion tests do not give. | `tests/ingestion/` | M |
| I8 | **Delete `memory/postgresql.py`** and `frontend/src/constants/*.js`. ~800 lines of dead code. | | S |
| I9 | **Ignore derived data** — add `out.csv`, `predictions.csv`, `memory_metadata.db`, `qdrant_db/` to `.gitignore`. | `.gitignore` | S |
| I10 | **Split `inference.predict` into two functions** (§2.1c) — `predict_supervised(...)` and `predict_dual_layer(artifacts, ...)`. | `inference.py` | M |
| I11 | **Fix `ATTACK_PROFILES`** (D9) to supply the full 42-feature vector. | `app.py:1205` | S |

### 4.3 Nice to have

| # | Task |
|---|---|
| N1 | **Improve the served model's weak spots** (D7) — `BOTNET` recall 0.74 on the served DNN, and no `INFILTRATION` class at all (the cleaned dataset has none; it would have to come from `data/raw/`). Lower urgency than originally stated: the served model's macro F1 is 0.97, not 0.84. |
| N2 | **Make `AnalysisAgent` earn its place.** `DeterministicRuleEngine` currently restates the detection in English and adds no signal. Give it something real: MITRE ATT&CK technique mapping, memory-based repeat-offender enrichment, or asset context. Otherwise consider folding it into detection. |
| N3 | **Add the LLM engine** behind the existing `AIEngine` / `DecisionEngine` protocols. The seams are already cut (`config/response_policy.yaml` has commented-out `OllamaDecisionEngine: AI_SUPERVISED` trust entries). This is the cheapest high-visibility feature in the repo. |
| N4 | **One real response executor** (iptables or nftables) behind an explicit opt-in flag. `ExecutorRegistry.register(..., override=True)` is already designed for it. |
| N5 | **Reproducibility manifest** from `train.py` (D10). |
| N6 | **Type-check and lint** — add `ruff` + `mypy` to `requirements-dev.txt`. The newer modules would pass almost immediately; `app.py` and `inference.py` would not, which is itself a useful signal. |
| N7 | **Model registry** — replace `resolve_model_path`'s hardcoded preference list with a small `artifacts/manifest.json` naming the active model and its metrics. |
| N8 | **Prometheus metrics** — `WorkerStats`, `BridgeStats`, `NormalizerStats`, and `ProcessorStats` are already structured counters; exposing them at `/metrics` is nearly free. |

### 4.4 Suggested order of work

1. **Week 1 — make it honest and installable:** C2, C3, C4, C5, C8, I9. (All small; removes every "it doesn't even start" and "the docs are wrong" objection.)
2. **Week 2 — make detection correct:** C1, C6, C7, I1, I11. (This is where the security value is.)
3. **Week 3 — make it coherent:** I2, I3, I5, I6, I8, I7.
4. **Week 4+ — make it better:** I4 (the `app.py` split), then N1 / N3.

---

## 5. Closing assessment

**What is genuinely impressive:** the `ingestion/`, `agents/response/`, `agents/coordinator/`, and `agents/learning/` modules are written to a standard well above typical project work. Their docstrings explain *why* each decision was made and what failure mode it prevents; the ingestion layer's units-conversion reasoning and the response layer's fail-closed trust model are the kind of thing that is normally learned only after an incident. The Redis and Docker hardening is real hardening, not checkbox hardening. The 416-test suite is honest — it tests behaviour, not implementation.

**What held it back** *(the detection-layer items below were fixed on 2026-08-02; see §3.9)*: the ML half — the part the whole system exists to serve — was never brought up to the same standard, and the two halves disagreed. The detection layer silently failed open on a missing model, silently zero-filled through one of its two ingress paths (with a 5,155-row all-BENIGN artifact in the repo proving it), never ran the anomaly detector it loaded into memory, and converted model confidence directly into automated blocking authority. The dashboard still streams fabricated log lines describing capabilities that do not exist.

**The model itself was never the problem.** The served DNN reaches macro F1 0.97 with 0.95 recall on web attacks. The failures were all in the *plumbing around it* — naming, units, wiring, and scoring — which is exactly why they were invisible: every individual component looked fine, and the accuracy number stayed at 99%.

None of these were hard to fix. What made them dangerous was that each one degraded the system toward "everything is safe" rather than toward a visible error — the most dangerous shape a security system's flaws can take.
