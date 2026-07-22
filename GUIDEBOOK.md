# Cyber Surakshya — Guidebook & Operations Manual

Welcome to **Cyber Surakshya**, a multi-agent, AI-driven cybersecurity platform. This document serves as a complete history of what was built and a perfect, step-by-step manual to run the entire project.

---

## Part 1: What Happened in the Project

The project evolved from a basic machine learning classifier into a robust, multi-agent cybersecurity operations shell. Here is the exact architectural journey:

### 1. The Machine Learning Core
- **Preprocessing (`preprocess.py`)**: We built a pipeline to process raw CICIDS2017 network flows, balancing classes using a hybrid oversampling/undersampling strategy and extracting the top 40 features using ANOVA F-scores.
- **Training (`train.py`)**: We trained RandomForest, ExtraTrees, and GradientBoosting models, ultimately combining them into a **Voting Ensemble** achieving ~99% accuracy across 8 attack classes (BENIGN, BOTNET, BRUTEFORCE, DDOS, DOS, INFILTRATION, PORTSCAN, WEBATTACK).
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

Open a terminal in the project root directory (`c:\Users\ACER\Downloads\files\`).

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
   ```

3. *(Optional)* **Train the model**:
   If the `artifacts/` folder does not contain `model.pkl`, `scaler.pkl`, `label_encoder.pkl`, and `feature_columns.json`, you must train the model. Place your CICIDS2017 CSV files in `data/raw/` and run:
   ```bash
   python train.py
   ```

4. **Start the FastAPI Backend:**
   ```bash
   uvicorn app:app --reload --host 127.0.0.1 --port 8000
   ```
   *The backend is now running at `http://127.0.0.1:8000`.*

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
   - The frontend securely sends an API request (with the `X-API-Key: cyber-surakshya-secret-key` header).
   - The backend `simulate-attack` endpoint crafts a synthetic security event.
   - The event passes through the LangGraph runtime (`DetectionAgent` → `AnalysisAgent`).
   - The backend responds with the exact threat score and blocked IP.
4. Navigate to the **Dashboard** and **Alerts** pages to see the dynamically generated threats populate your SOC panels!

---
> [!IMPORTANT]
> **Authentication Note:** If you write external scripts to query the API (e.g., via `curl` or Python), you must include the header `X-API-Key: cyber-surakshya-secret-key`, otherwise you will receive a `403 Forbidden` response.
