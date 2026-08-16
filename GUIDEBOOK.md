# Cyber Surakshya — Guidebook & Operations Manual

Welcome to **Cyber Surakshya**, a multi-agent, AI-driven cybersecurity platform. This document serves as a complete history of what was built and a perfect, step-by-step manual to run the entire project.

---

## Part 1: What Happened in the Project

The project evolved from a basic machine learning classifier into a robust, multi-agent cybersecurity operations shell. Here is the exact architectural journey:

### 1. The Machine Learning Core
- **Preprocessing (`preprocess.py`)**: We built a pipeline to process raw CICIDS2017 network flows, balancing classes using a hybrid oversampling/undersampling strategy and extracting the top 40 features using ANOVA F-scores.
- **Training (`train.py`)**: We trained RandomForest, GradientBoosting, a DNN (`MLPClassifier`), and a Voting Ensemble across **7** classes: BENIGN, BOTNET, BRUTEFORCE, DDOS, DOS, PORTSCAN, WEBATTACK. There is **no INFILTRATION class** — the cleaned dataset contains no infiltration rows.
  - The **served** model is the DNN (`artifacts/model_DNN.pkl`), chosen by `inference.resolve_model_path`. It reaches **macro F1 0.97** (accuracy 0.9971), with recall 0.95 on web attacks and 0.74 on botnet C2.
  - Quote the **macro** F1, not accuracy. Accuracy is ~99% for every model here because four classes make up ~99% of the rows; the Voting Ensemble reads 0.9943 accuracy but only **0.10 recall on WEBATTACK**.
- **Inference & Zeek Translation (`inference.py`)**: We developed an inference bridge capable of predicting from JSON, CSV, and natively translating **Zeek `conn.log`** fields into CICIDS2017 features.

### 2. The Platform Domain
- **Schemas (`cyber_surakshya/platform/schemas`)**: We implemented strict Pydantic v2 models for `SecurityEvent`, `DetectionResult`, `AnalysisResult`, and `Alert`, utilizing `extra="forbid"` to ensure data purity.
- **Risk & Severity**: Created a deterministic mapping between a 0–100 numeric risk score and a 5-tier Severity scale (INFO to CRITICAL).

### 3. LangGraph Orchestration & Agents
- **Graph Shell (`graph/`)**: Implemented LangGraph's `StateGraph` using an append-only `PlatformSharedState` TypedDict. The `GraphRuntime` handles state compilation, validation, and memoization.
- **Agent Nodes (`agents/`)**: 
  - `DetectionAgent`: Reads a `SecurityEvent`, invokes the ML model via the `IDSDetectionAdapter`, and appends a `DetectionResult`.
  - `AnalysisAgent`: Reads the detection, invokes the `DeterministicRuleEngine`, and appends an `AnalysisResult`.

### 4. API & Frontend Integration
- **FastAPI Backend (`app.py`)**: Wrapped the graph and inference engine in a high-performance asynchronous REST API.
- **Security Enhancements**: 
  - Replaced hardcoded file paths with environment variable/relative-path awareness.
  - Locked down CORS strictly to local frontend development ports.
  - Secured endpoints using the `X-API-Key` HTTP header.
- **Frontend Dashboard (`frontend/`)**: Connected a modern React/Vite dashboard to the backend. Features like `simulate-attack` were wired directly to the LangGraph runtime to demonstrate the multi-agent pipeline generating dynamic alerts.

---

## Part 2: Perfect Manual to Run the Project

Follow these steps exactly to run the backend and frontend simultaneously.

### Step 1: Backend Setup (Python)

Open a terminal in the project root directory.

1. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv

   # On Windows:
   .venv\Scripts\activate
   # On Linux/Mac:
   # source .venv/bin/activate
   ```

2. **Install all backend dependencies:**
   ```bash
   pip install -r requirements.txt
   # for tests and linting as well:
   pip install -r requirements-dev.txt
   ```
   > `sentence-transformers` pulls in torch (~2 GB). It backs the memory
   > layer's semantic search; there is no lighter path today.

3. **Create your `.env`** — the server **refuses to start without an API key**:
   ```bash
   cp .env.example .env
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
   Put that value in **two** files, and they must match:

   | File | Variable |
   |---|---|
   | `.env` | `CYBER_SURAKSHYA_API_KEY=<value>` |
   | `frontend/.env` | `VITE_API_KEY=<value>` |

4. *(Only if `artifacts/` is empty)* **Train the model.** The repository ships
   trained artifacts, so this is normally unnecessary. To retrain, place
   `cicids2017_cleaned.csv` in `data/` and run:
   ```bash
   python train.py

   # then regenerate the two derived artifacts:
   python scripts/build_attack_profiles.py   # simulation profiles
   ```
   `train.py` writes `artifacts/manifest.json`, which records **which model is
   served** and why. Model selection is macro F1 with a per-class recall floor —
   *not* accuracy, and not weighted F1. See "A note on model selection" below.

5. **Start the FastAPI Backend:**
   ```bash
   uvicorn app:app --reload --host 127.0.0.1 --port 8000
   ```
   *The backend is now running at `http://127.0.0.1:8000`.*

6. **Confirm it can actually detect** — `/health` scores a real flow, so a
   200 means the model, scaler and encoder all agree:
   ```bash
   curl http://127.0.0.1:8000/health
   ```
   A `503` means detection is **disabled**, with the reason in the body. The
   platform fails closed: it will not run with a missing or mismatched model.

### Step 2: Frontend Setup (Node.js)

Open a **new** terminal (keep the backend terminal running). Navigate to the `frontend` folder:
```bash
cd frontend
```

1. **Install JavaScript dependencies:**
   ```bash
   npm install
   ```

2. **Start the Vite development server:**
   ```bash
   npm run dev
   ```
   *The terminal will output a localhost URL (usually `http://localhost:5173`).*

### Step 3: Accessing the Dashboard

1. Open your web browser and navigate to the Vite frontend URL (`http://localhost:5173`).
2. Navigate to the **Simulation** tab in the sidebar.
3. Click the **Generate Attack** button.
   - The frontend sends an API request with the `X-API-Key` header, read from `VITE_API_KEY`.
   - The backend `simulate-attack` endpoint picks one of seven flow profiles — each a **median feature vector over real labelled CICIDS2017 flows**, generated by `scripts/build_attack_profiles.py` into `artifacts/attack_profiles.json`.
   - The event passes through the LangGraph runtime (`CoordinatorAgent` → `DetectionAgent` → `AnalysisAgent` → `DecisionAgent` → `ResponseAgent`).
   - The backend responds with the detection, the decision, and what the ResponseAgent actually did.
4. Navigate to the **Dashboard** and **Alerts** pages to see the dynamically generated threats populate your SOC panels!

---
> [!IMPORTANT]
> **Authentication.** The API key is **no longer hardcoded**. It was previously the literal `cyber-surakshya-secret-key`, committed in both `app.py` and `frontend/src/api/axios.js`.
>
> Set it before starting the backend — `app.py` refuses to start without it:
>
> ```bash
> # generate one
> python -c "import secrets; print(secrets.token_urlsafe(32))"
> ```
>
> Put the value in **two** places, and they must match:
>
> | File | Variable |
> |---|---|
> | `.env` | `CYBER_SURAKSHYA_API_KEY=<value>` |
> | `frontend/.env` | `VITE_API_KEY=<value>` |
>
> External scripts must send the same value:
>
> ```bash
> curl -H "X-API-Key: $CYBER_SURAKSHYA_API_KEY" http://localhost:8000/alerts
> ```
>
> Without the header you get `403 Forbidden`. `GET /health` is deliberately public.

---

## Part 3: Reference

### Project layout

```
app.py                    application assembly only (112 lines)
api/
  security.py             API-key auth
  runtime.py              platform singletons + construction (the `platform` object)
  projections.py          stored records -> dashboard shapes
  routers/                8 routers, one per domain
inference.py              model serving: predict_supervised / predict_dual_layer
train.py, preprocess.py   training pipeline
adapters/                 detection (ML bridge) + response (executors)
agents/                   detection, analysis, decision, response, coordinator, learning
graph/                    LangGraph shell
ingestion/                capture -> cicflowmeter -> Redis -> pipeline
memory/                   memory abstraction (Qdrant + SQLite)
observability/            live event log (/feed) + Prometheus metrics (/metrics)
cyber_surakshya/platform/ domain schemas, enums, risk model
scripts/                  build_attack_profiles.py, build_manifest.py
config/                   ingestion_policy.yaml, response_policy.yaml
```

### Public endpoints (no API key)

| Endpoint | Purpose |
|---|---|
| `GET /health` | Scores a real flow. `503` means detection is disabled. |
| `GET /metrics` | Prometheus text exposition. |
| `GET /feed` | SSE stream of **real** agent log events. |
| `GET /feed/recent` | Last N real events, for a dashboard that just loaded. |

Everything else requires `X-API-Key`.

### A note on model selection

Four models are trained. Three of them — RandomForest, GradientBoosting and
VotingEnsemble — score **above 0.99 weighted F1** while catching **8–10% of
WEBATTACK**. The served DNN catches 95%.

Accuracy and weighted F1 cannot tell these apart, because BENIGN, DDOS, DOS and
PORTSCAN are ~99% of the rows. Quote **macro F1**.

`artifacts/manifest.json` records the choice and `inference.resolve_model_path`
honours it, so dropping a `model.pkl` built from the wrong estimator can no
longer silently blind the detector. Regenerate it with:

```bash
python scripts/build_manifest.py
```

### Development

```bash
python -m pytest -q            # 446 tests
python -m ruff check .         # lint (config in pyproject.toml)
```

### Live capture (optional)

Capture is off by default — starting a packet capture is a privileged act and
must be an explicit operator decision.

```bash
docker compose up -d redis     # stream transport
curl -H "X-API-Key: $CYBER_SURAKSHYA_API_KEY" localhost:8000/ingestion/preflight
```

`preflight` reports every blocker (capture backend, Redis, feature contract,
runtime) before anything starts. Set the interface in
`config/ingestion_policy.yaml` — there is deliberately no default, because the
platform must never guess which network to tap.

### Known limitations

| Limitation | Detail |
|---|---|
| **No INFILTRATION detection** | The cleaned dataset contains zero infiltration rows. Seven classes is the ceiling for this data. |
| **BOTNET recall 0.74** | Roughly one in four C2 flows is missed, and C2 implies an already-compromised host. |
| **Containment is simulated** | `SimulatedContainmentExecutor` keeps an in-process ledger. No firewall or EDR integration exists; adding one is a startup wiring change. |
| **No LLM engine** | The `DecisionEngine` protocol and the `AI_SUPERVISED` trust tier in `config/response_policy.yaml` are ready for one. |
| **Memory is single-writer** | Embedded Qdrant allows one process at a time. A second server makes `/learning/*` and `/alerts` report `503`. |
