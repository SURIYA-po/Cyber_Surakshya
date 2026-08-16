# 4. Work Details

> *Drafting note (delete before submission): section numbers assume this is
> Chapter 4. Renumber if your Methodology chapter differs. All quantitative
> results below are taken from `artifacts/evaluation_report.txt` and
> `artifacts/manifest.json` produced by this project's own training run.*

---

## 4.1 Overview of the Implemented System

This chapter describes the concrete implementation of **Cyber Surakshya**, the
multi-agent intrusion detection platform proposed in the previous chapter. The
work is presented in the order it was built: first the machine-learning core
that decides whether a network flow is hostile, then the software platform that
acts on that decision, and finally the testing and evaluation that establish
whether the two work correctly together.

The finished system consists of six cooperating parts:

| Layer | Responsibility | Key modules |
|---|---|---|
| **Ingestion** | Captures live network traffic and converts it to numerical flow records | `ingestion/` |
| **Detection** | Classifies each flow using the trained model | `inference.py`, `adapters/detection/` |
| **Analysis** | Interprets the detection and attaches supporting evidence | `agents/analysis/` |
| **Decision** | Applies a security policy to choose a response action | `agents/decision/` |
| **Response** | Authorises and executes (or refuses) the chosen action | `agents/response/` |
| **Learning** | Reviews historical outcomes and proposes improvements | `agents/learning/` |

A *flow* is the central unit of data throughout this system. A flow is one
conversation between two computers — identified by source IP, source port,
destination IP, destination port and protocol — summarised as a fixed list of
numeric measurements such as duration, packet counts, byte counts and inter-arrival
timings. The model never inspects packet contents; it reasons only about these
statistical summaries. This is what allows detection to work on encrypted traffic
and what makes the system privacy-preserving by design.

**[Insert Figure: System Architecture Diagram — six layers with data flow arrows from Ingestion through to Learning]**

---

## 4.2 Data Handling and Preprocessing

### 4.2.1 Dataset Description

The system was trained on a cleaned derivative of the **CICIDS2017** dataset, a
widely used public benchmark of labelled network traffic produced by the Canadian
Institute for Cybersecurity. The working file, `data/cicids2017_cleaned.csv`,
contains **2,520,751 rows and 53 columns** (52 numerical flow features plus one
label column named `Attack Type`).

The raw label distribution is severely imbalanced, which proved to be the single
most important characteristic of this dataset for the results reported later:

| Raw label | Normalised class | Rows | Share of dataset |
|---|---|---|---|
| Normal Traffic | BENIGN | 2,095,057 | 83.11% |
| DoS | DOS | 193,745 | 7.69% |
| DDoS | DDOS | 128,014 | 5.08% |
| Port Scanning | PORTSCAN | 90,694 | 3.60% |
| Brute Force | BRUTEFORCE | 9,150 | 0.36% |
| Web Attacks | WEBATTACK | 2,143 | 0.09% |
| Bots | BOTNET | 1,948 | 0.08% |
| **Total** | | **2,520,751** | **100%** |

Two observations follow directly from this table and shape the rest of the chapter.

First, the four largest classes account for **99.5%** of all rows. Any metric that
averages across *samples* rather than across *classes* will therefore be dominated
by these four, and will be almost blind to the remaining three. This is the reason
Section 4.7 reports **macro-averaged** metrics as the headline result.

Second, the two rarest classes — WEBATTACK and BOTNET — are precisely the two
attack families a security analyst most needs help detecting, since both indicate
a targeted intrusion rather than a noisy volumetric event.

**[Insert Figure: Class Distribution Bar Chart]**
*(This figure is already produced by the training pipeline at
`figures/class_distribution.png`.)*

### 4.2.2 Stratified Sampling

Training on all 2.5 million rows is unnecessary and computationally wasteful. The
`load_dataset()` function in `preprocess.py` performs a single fast pass over the
file to count labels, then samples a stratified subset with a default target of
**500,000 rows**. The sampling budget applies:

- a hard **cap of 120,000 rows on BENIGN**, preventing the majority class from
  overwhelming the sample; and
- a **floor of 3,000 rows for minority classes**, ensuring rare attacks survive
  the reduction.

This approach preserves the presence of every class while making training feasible
on standard hardware.

### 4.2.3 Label Normalisation

The `normalize_labels()` function maps the dataset's raw label strings onto seven
canonical class names. A direct dictionary lookup handles the known labels; a
keyword-based fallback (matching substrings such as `BRUTE`, `PATATOR`, `SCAN`,
`XSS`) catches variant spellings. Rows whose label matches neither route are
**dropped and counted**, rather than silently assigned to a default class — an
important safeguard, since a misassigned label corrupts training in a way that is
invisible in the final metrics.

**An important limitation is recorded here.** The cleaned dataset contains **no
infiltration records at all**. Consequently the system supports **seven classes,
not eight**, and cannot detect infiltration or lateral movement regardless of model
quality. This is a property of the training data, not of the architecture, and is
listed as future work in Chapter 6.

### 4.2.4 Data Cleaning

The `clean_data()` function performs four operations in sequence:

1. **Column-name normalisation** — surrounding whitespace is stripped, since
   several CICIDS2017 distributions ship headers with leading spaces.
2. **Numeric coercion** — every feature column is forced to a numeric type; values
   that cannot be parsed become `NaN`.
3. **Infinite and missing value handling** — flow-rate features such as
   `Flow Bytes/s` are undefined for a single-packet flow and appear as infinity.
   These are replaced with `NaN` and then filled with the **column median**. The
   median is chosen over the mean because these features are heavily right-skewed;
   a mean would be dragged toward a value no real flow ever takes.
4. **Duplicate removal** — exact duplicate rows are dropped.

### 4.2.5 Feature Selection

Feature selection reduces the 52 raw features to a smaller, more informative set.
The `select_features()` function uses a **combined ranking** rather than a single
statistical test:

- **ANOVA F-score** measures how strongly each feature separates the classes
  linearly.
- **Mutual Information** measures statistical dependence between feature and label,
  including non-linear relationships. It is computed on a 30,000-row subsample for
  tractability.

Both score vectors are min-max normalised to a common 0–1 range and averaged, and
the **top 40** features by combined score are selected. Using two complementary
criteria avoids the failure mode of either used alone: ANOVA misses non-linear
relationships, while Mutual Information is noisier on small samples.

A **domain-knowledge override** is then applied. A list of 19 `ZEEK_PRIORITY_FEATURES`
— features that can be derived from live network telemetry — is force-included if
not already selected. This is a deliberate engineering trade-off: a marginally less
statistically optimal feature set that can actually be computed from live traffic is
more valuable than an optimal set that cannot. After this step the final feature
count is **42**.

**[Insert Figure: Feature Importance — Top 20 Features]**
*(Available at `figures/fi_RandomForest.png`.)*

**[Insert Table: Final 42 Selected Features]**
*(The full ordered list appears in `artifacts/feature_columns.json` and at the end
of `artifacts/evaluation_report.txt`.)*

### 4.2.6 Class Balancing, Scaling and Splitting

The order of these final three operations matters and was chosen carefully:

1. **Stratified train/test split (80/20)** is performed **first**, producing a test
   set of **100,088 samples**. Splitting before balancing ensures the test set
   retains the natural, imbalanced class distribution — so reported performance
   reflects realistic operating conditions rather than an artificially easy problem.
2. **StandardScaler is fitted on the training set only**, then applied to both
   splits. Fitting on the full dataset would leak information about the test
   distribution into the model, inflating results.
3. **Hybrid class balancing** is applied to the **training set only**, capping
   BENIGN at 80,000 samples and oversampling minority classes to a floor of 2,000.

**[Insert Figure: Class Distribution Before and After Balancing]**

---

## 4.3 Development Process and System Architecture

The platform was developed incrementally in six phases, each producing a
testable artefact before the next began.

### 4.3.1 Phase 1 — Machine Learning Core

The first phase produced the preprocessing pipeline (`preprocess.py`), the training
pipeline (`train.py`) and a serving module (`inference.py`). The output of this
phase is a set of serialised artefacts:

| Artefact | Contents |
|---|---|
| `model_<name>.pkl` | Each trained classifier |
| `scaler.pkl` | The fitted StandardScaler |
| `label_encoder.pkl` | The class-name ↔ integer mapping |
| `feature_columns.json` | The ordered list of 42 expected features |
| `iforest.pkl`, `autoencoder.pkl` | The unsupervised anomaly layer |
| `anomaly_thresholds.json` | Decision thresholds for the anomaly layer |
| `manifest.json` | Which model is served, and the provenance of the run |

**[Insert Screenshot: Terminal output of `python train.py` showing model training progress and per-model evaluation]**

### 4.3.2 Phase 2 — Domain Model

Rather than passing untyped dictionaries between components, a strict domain model
was defined using **Pydantic v2** schemas in `cyber_surakshya/platform/`. Every
schema sets `extra="forbid"`, meaning an unexpected field raises an error rather
than being silently ignored. The core schemas are `SecurityEvent`, `DetectionResult`,
`AnalysisResult`, `DecisionResult` and `ResponseResult`.

These schemas also carry **invariants** — rules the data must always satisfy. For
example, `DetectionResult` rejects any record where the status is `BENIGN` but the
anomaly flag is set, because that combination is logically contradictory. Enforcing
such rules at the data layer means an entire class of bug cannot propagate through
the system.

**[Insert Screenshot: `cyber_surakshya/platform/schemas/detection_result.py` showing the schema definition and its validators]**

### 4.3.3 Phase 3 — Agent Orchestration

The agents are wired together using **LangGraph**, a library for expressing
multi-step workflows as a graph. The design uses a **hub-and-spoke** topology: a
`CoordinatorAgent` sits at the centre and decides which agent runs next, and every
worker agent returns to the coordinator when finished.

This topology was chosen over a simple linear chain for a specific reason. Each
agent processes exactly one pending item per invocation, so a linear chain
processing a batch of *N* events would handle the first and silently discard the
rest. The coordinator instead maintains a **work queue** derived from the current
state and drains it stage by stage.

The coordinator also implements two safety mechanisms:

- **Stall detection** — if a dispatched agent produces no new output, that stage is
  excluded from further routing. Without this, a failing agent would be dispatched
  to indefinitely, producing a live-lock.
- **An iteration budget** — a hard ceiling on dispatches per run, acting as a
  backstop behind stall detection.

**[Insert Figure: Agent Orchestration Graph — coordinator hub with detection, analysis, decision and response spokes]**

### 4.3.4 Phase 4 — The Agents

| Agent | Input | Output |
|---|---|---|
| `DetectionAgent` | `SecurityEvent` | `DetectionResult` (label, confidence, risk) |
| `AnalysisAgent` | `DetectionResult` | `AnalysisResult` (severity, evidence) |
| `DecisionAgent` | `AnalysisResult` | `DecisionResult` (action, approval requirement) |
| `ResponseAgent` | `DecisionResult` | `ResponseResult` (execution outcome) |
| `LearningAgent` | Historical records | `LearningReport` (metrics, recommendations) |

Each agent has a deliberately narrow contract. The `ResponseAgent`, for instance,
reads *only* `DecisionResult` — never the original detection or event. This means it
cannot second-guess the decision; it may refuse or downgrade an action, but never
escalate one.

The `LearningAgent` is **not** a pipeline node. It operates over accumulated history
rather than individual events, so registering it in the graph would re-derive
platform-wide metrics on every single flow. It is invoked on demand instead.

### 4.3.5 Phase 5 — Live Traffic Ingestion

To operate on real traffic rather than dataset replay, an ingestion pipeline was
built with the following stages:

```
Network interface
  → dumpcap (packet capture, headers only)
  → rotating .pcap files
  → cicflowmeter (packet → flow conversion)
  → FlowNormalizer (feature contract enforcement)
  → Redis Streams (buffering and durability)
  → PipelineBridge (batch → SecurityEvents)
  → Agent pipeline
```

Two design decisions in this layer are worth recording:

**Headers-only capture.** Packets are captured with a *snaplen* of 96 bytes,
meaning only protocol headers reach disk. Every flow feature is computable from
headers, so payloads are pure liability — they would write credentials, tokens and
personal data to disk for no analytical gain. This is the highest-value privacy
control in the system.

**Redis Streams as a buffer.** Placing a durable queue between capture and analysis
decouples the two rates. If the agent pipeline slows, flows accumulate in the queue
rather than being dropped, and an unacknowledged batch is redelivered after a
consumer crash.

**[Insert Screenshot: Live Capture page of the dashboard showing capture status, interface selection and flow counters]**

### 4.3.6 Phase 6 — API and Dashboard

The platform is exposed through a **FastAPI** backend organised into eight
domain-specific routers, and a **React/Vite** dashboard. The API surface comprises
45 endpoints. Authentication uses an `X-API-Key` header supplied from environment
configuration; the server refuses to start if the key is unset.

Four endpoints are deliberately public: `/health`, `/metrics`, `/feed` and
`/feed/recent`. A health check behind a credential is one a load balancer cannot
use, and a metrics endpoint behind a rotating credential silently stops working.

**[Insert Screenshot: Main Dashboard showing threat statistics, severity chart and recent alerts]**

**[Insert Screenshot: Alerts page with the alert table, severity badges and filtering controls]**

**[Insert Screenshot: Alert Detail page showing the detection, analysis summary, decision rationale and response outcome]**

**[Insert Screenshot: FastAPI interactive documentation at `/docs` showing the full endpoint list]**

---

## 4.4 The Detection Layer

The detection layer is the entry point of the entire pipeline: every downstream
component transforms its output, and no other component examines the raw flow.
Its correctness therefore bounds the correctness of the whole system.

### 4.4.1 Dual-Layer Design

Detection combines two independent models:

**Layer 1 — Supervised classifier.** A trained model assigns the flow to one of the
seven known classes and reports a confidence value.

**Layer 2 — Unsupervised anomaly detector.** An **Isolation Forest** and an
**autoencoder**, both trained on BENIGN traffic *only*, judge whether the flow
resembles normal traffic at all. The Isolation Forest flags flows that are easy to
isolate from the bulk of the data; the autoencoder flags flows it cannot accurately
reconstruct. Fixed thresholds calibrated during training convert each score to a
boolean.

The two layers are combined as follows:

| Classifier says | Anomaly layer says | Final status |
|---|---|---|
| BENIGN | normal | **BENIGN** |
| BENIGN | anomalous | **INCONCLUSIVE** |
| Attack (confidence ≥ threshold) | either | **DETECTED** |
| Attack (confidence < threshold) | either | **INCONCLUSIVE** |

The second row is the entire justification for training a second model. A supervised
classifier can only choose among the classes it has seen, so a genuinely novel attack
is confidently sorted into the nearest known class — potentially BENIGN. When the
anomaly layer disagrees with a BENIGN verdict, the honest answer is "uncertain",
not "safe".

**[Insert Figure: Dual-Layer Detection Decision Flowchart]**

### 4.4.2 Risk Scoring

Each detection is assigned a numeric risk score on a 0–100 scale, which downstream
policy uses to choose an action. Risk is computed as:

```
risk = base_risk(predicted_class) × confidence
```

with an additional upward adjustment when the anomaly layer independently agrees.
The per-class base values encode **consequence**, not detectability:

| Class | Base risk | Rationale |
|---|---|---|
| BOTNET | 95 | Command-and-control traffic implies the host is already compromised |
| WEBATTACK | 90 | SQL injection and XSS are direct data-breach vectors |
| DDOS | 85 | Availability impact, but no compromise implied |
| DOS | 75 | Availability impact, smaller blast radius |
| BRUTEFORCE | 70 | Credential attack, frequently unsuccessful and very noisy |
| PORTSCAN | 40 | Reconnaissance only; constant background noise on any public interface |
| *(unknown class)* | 60 | Mid-range default so a retrained model with new classes is neither ignored nor over-escalated |

This design replaced an earlier formulation in which risk was simply
`confidence × 100`. That formulation made risk a restatement of model certainty and
ignored what the attack actually was. Because the model is over 99% confident on its
common classes, essentially every detection scored above 80 — the threshold at which
the response policy performs automatic containment. A routine port scan and a
volumetric denial-of-service attack therefore triggered identical automated blocking.
Separating consequence from certainty resolves this; Section 4.7.5 shows the effect.

### 4.4.3 Decision Policy

The `DecisionAgent` evaluates an ordered table of seven policy rules, first match
winning. Rules are expressed as pure data — thresholds on severity, risk, confidence,
detection status and prior-incident count — with no attack-specific names encoded in
logic. Adding a rule for a new threat therefore requires no code change.

**[Insert Table: Decision Policy Rule Table — rule name, conditions, action, approval requirement]**

### 4.4.4 Response Authorisation

Before any action executes, an `ActionGuard` evaluates it against several
independent controls:

- **Engine trust tier** — deterministic rule engines may perform destructive
  actions; a language-model engine is restricted to non-destructive ones.
- **Protected targets** — loopback, link-local, multicast and broadcast ranges
  are refused outright, as are operator-designated critical hosts.
- **Blast radius** — a limit on destructive actions per incident, per target
  within a time window, and globally per minute.

Actions that fail a check are **downgraded** (typically to a notification) rather
than silently dropped, and every verdict is recorded on the resulting
`ResponseResult`. Only simulation-safe executors ship with the system; no real
firewall or endpoint integration is enabled by default.

**[Insert Screenshot: Response page showing executed actions, guard verdicts and pending approvals]**

---

## 4.5 Model Training

### 4.5.1 Models Evaluated

Four classifiers were trained on identical data with a fixed random seed (42) to
ensure comparability:

| Model | Configuration |
|---|---|
| **Random Forest** | 300 trees, unrestricted depth, `max_features='sqrt'`, balanced class weights |
| **Gradient Boosting** | Histogram-based, 300 iterations, depth 8, learning rate 0.05, L2 = 1.0, early stopping |
| **Deep Neural Network** | Multi-layer perceptron, hidden layers (512, 256, 128), ReLU, Adam, α = 1e-4, batch 256, adaptive learning rate, early stopping on a 10% validation split |
| **Voting Ensemble** | Soft voting over the three models above |

All four use **balanced class weighting** where supported, instructing the learner
to penalise errors on rare classes more heavily — a partial countermeasure to the
imbalance documented in Section 4.2.1.

### 4.5.2 Anomaly Layer Training

The Isolation Forest and autoencoder were trained on **BENIGN samples only**, with a
contamination parameter of 0.05. Training on benign traffic alone is what allows the
layer to flag genuinely unfamiliar behaviour rather than only the attack types
present in the dataset. Thresholds were calibrated on the training distribution and
persisted to `artifacts/anomaly_thresholds.json`.

**[Insert Figure: Training vs Validation Loss Curve for the DNN]**
*(Generated from the `loss_curve_` and `validation_scores_` attributes of the fitted
`MLPClassifier`. If this figure was not saved during your run, it can be regenerated
by re-fitting with the same seed and plotting these attributes.)*

**[Insert Screenshot: Training console output showing early stopping triggering on the DNN]**

---

## 4.6 Testing and Evaluation Methodology

Testing was conducted at four levels. This structure is reported in detail because
the most consequential defects found in this project were **not** caught by model
evaluation — they were caught by integration testing, and they were invisible to
accuracy metrics.

### 4.6.1 Level 1 — Automated Unit and Integration Tests

An automated suite of **446 tests** covers the platform. Its distribution reflects
where correctness is hardest to verify by inspection:

| Area | Focus |
|---|---|
| Platform schemas | Validation rules and invariants |
| Ingestion | Feature contract, unit conversion, stream durability, capture lifecycle |
| Agents | Routing, stall detection, policy evaluation, response authorisation |
| Adapters | Detection output mapping, executor behaviour |
| Memory | Storage, retrieval, concurrency |
| Metrics & manifest | Output format and model-selection rules |

Stream tests run against an in-process Redis substitute rather than a live server,
on the principle that a durability test requiring external infrastructure is a test
that gets skipped — and durability guarantees are exactly the ones whose failure
goes unnoticed until production.

**[Insert Screenshot: Terminal output of `python -m pytest -q` showing 446 tests passing]**

### 4.6.2 Level 2 — Model Evaluation

Each classifier was evaluated on the held-out 100,088-sample test set using accuracy,
precision, recall, F1-score and ROC-AUC, computed both **weighted** (averaged across
samples) and **macro** (averaged across classes). Per-class confusion matrices were
generated for each model. Results are presented in Section 4.7.

### 4.6.3 Level 3 — Interface Contract Testing

This level tests the *boundaries between components* rather than the components
themselves, and it revealed the most serious defect found during the project.

The trained model expects features under CICIDS2017 names in specific units, for
example `Flow Duration` measured in **microseconds**. The live capture tool used for
real traffic emits `flow_duration` in **seconds**. Two independent mismatches
therefore separated the live pipeline from the model:

1. **Naming.** The tool emits `snake_case` names; the model expects `Title Case`.
   None of the 42 required features matched by name.
2. **Units.** Thirteen time-domain features are expressed in seconds by the capture
   tool and microseconds by the dataset — a factor of one million.

Neither mismatch raises an error. Unmatched features are filled with zero, and the
model dutifully classifies the resulting near-empty vector. The consequence was
observable in a stored prediction file covering 5,155 real captured flows:

| Metric | Value | Interpretation |
|---|---|---|
| Predicted class | BENIGN for all 5,155 flows | No variation whatsoever |
| Mean confidence | 1.000 | Maximum certainty |
| Standard deviation of confidence | 0.000 | Identical input for every row |
| Features populated | 0 of 42 | Every value was zero-filled |

**Zero variance in confidence across five thousand distinct flows is the signature
of a constant input vector, not of genuinely benign traffic.** The detector was
reporting the network clean with maximum confidence while receiving no information
at all. Critically, *every standard evaluation metric remained at 99%*, because
those metrics are computed on the dataset, not on live traffic.

The remediation introduced an explicit feature-contract module that maps every
source column to its model feature and converts the thirteen time features, while
listing the four per-second rate features separately so a test can assert they are
*never* scaled — scaling a rate by mistake is the same bug with the sign reversed.
A coverage guard was added so that an input matching fewer than half the expected
features raises an error rather than producing a confident, meaningless label.

Re-running the same 5,155 flows after remediation:

| Metric | Before | After |
|---|---|---|
| Features mapped | 0 / 42 | **42 / 42** |
| Non-zero values in scaled matrix | 0% | **100%** |
| Flows flagged by anomaly layer | 0 | **60** |
| `Flow Duration` (median) | 0 (zero-filled) | 966 µs |
| `Destination Port` (median) | 0 (zero-filled) | 53 (DNS) |

**[Insert Table: Feature Contract Verification — Before vs After Remediation]**

**[Insert Screenshot: Console output showing "Detected Python cicflowmeter output: renamed 42 columns, converted 13 time features seconds -> microseconds"]**

### 4.6.4 Level 4 — End-to-End Validation

Two end-to-end tests confirm the complete chain.

**Synthetic packet capture test.** A small TCP conversation (handshake, HTTP request
and response, teardown) is generated programmatically and written to a real capture
file, then processed through the entire chain. The test asserts not merely that a
detection was produced — a zero-filled vector produces one of those too — but that
the features **arrived populated**: 36 of 42 features non-zero, `Flow Duration`
correctly reading 95,000 µs for a 0.095-second conversation, and rate features
correctly left unscaled.

**Class-profile validation.** A representative flow vector was computed for each of
the seven classes by taking the **median** of every feature over real labelled
samples of that class. The median was chosen over the mean because these features are
heavily skewed — a mean produces a vector no real flow resembles, whereas a median is
an actual point within the class. Each profile was then passed through the complete
pipeline.

**All seven profiles were classified as their own class**, confirming that the
serving path reproduces training-time behaviour.

**[Insert Table: Class Profile Validation — Profile, Predicted Class, Confidence, Anomaly Flag, Final Status]**

---

## 4.7 Results and Performance Analysis

### 4.7.1 Aggregate Performance

All four models were evaluated on the same 100,088-sample held-out test set.

| Model | Accuracy | Precision (wt.) | Recall (wt.) | F1 (wt.) | **F1 (macro)** | **Recall (macro)** | ROC-AUC |
|---|---|---|---|---|---|---|---|
| Random Forest | 0.9942 | 0.9944 | 0.9942 | 0.9924 | 0.8414 | 0.8129 | 0.9975 |
| Gradient Boosting | 0.9943 | 0.9944 | 0.9943 | 0.9925 | 0.8443 | 0.8157 | 1.000 |
| **Deep Neural Network** | **0.9971** | **0.9971** | **0.9971** | **0.9970** | **0.9657** | **0.9543** | 1.000 |
| Voting Ensemble | 0.9943 | 0.9943 | 0.9943 | 0.9926 | 0.8471 | 0.8157 | 1.000 |

**[Insert Table: Model Metrics Comparison Table]**

**[Insert Figure: Model Comparison Chart (Accuracy, Precision, Recall, F1-Score)]**
*(Available at `figures/model_comparison.png`.)*

Read by accuracy alone, all four models appear equivalent — separated by less than
0.3 percentage points, all above 99%. **This reading is misleading**, and the reason
is visible only in the macro columns, where the four models separate by more than
twelve points.

### 4.7.2 Per-Class Analysis

The following table gives per-class **recall** — the proportion of each attack type
that the model successfully catches. This is the most operationally meaningful
metric for an intrusion detection system, because a missed attack is far more costly
than a false alarm.

| Class | Test samples | **DNN** | Random Forest | Gradient Boosting | Voting Ensemble |
|---|---|---|---|---|---|
| BENIGN | 24,000 | 1.00 | 1.00 | 1.00 | 1.00 |
| DDOS | 22,854 | 1.00 | 1.00 | 1.00 | 1.00 |
| DOS | 34,590 | 1.00 | 1.00 | 1.00 | 1.00 |
| PORTSCAN | 16,192 | 1.00 | 1.00 | 1.00 | 1.00 |
| BRUTEFORCE | 1,633 | 0.99 | 1.00 | 1.00 | 1.00 |
| **BOTNET** | 390 | **0.74** | 0.61 | 0.61 | 0.61 |
| **WEBATTACK** | 429 | **0.95** | **0.08** | **0.10** | **0.10** |

This table is the central experimental result of the project.

The three tree-based and ensemble models achieve **0.08–0.10 recall on WEBATTACK**,
meaning they detect roughly **one web attack in ten** and miss the other nine. They
nonetheless report over 99% accuracy, because the 429 web-attack samples represent
0.43% of the test set — small enough that missing almost all of them barely moves
the aggregate.

The Deep Neural Network reaches **0.95 recall on WEBATTACK** with 0.92 precision,
and the highest BOTNET recall at 0.74. Its macro F1 of **0.9657** exceeds the next
best model by 0.119.

**[Insert Figure: Confusion Matrix for DNN]** *(`figures/cm_DNN.png`)*

**[Insert Figure: Confusion Matrix for Random Forest]** *(`figures/cm_RandomForest.png`)*

**[Insert Figure: Confusion Matrix for Gradient Boosting]** *(`figures/cm_GradientBoosting.png`)*

**[Insert Figure: Confusion Matrix for Voting Ensemble]** *(`figures/cm_VotingEnsemble.png`)*

**[Insert Figure: Per-Class Recall Comparison — grouped bar chart across the four models]**

### 4.7.3 Interpretation

Three conclusions follow.

**Aggregate metrics are unsafe for imbalanced security data.** A model detecting
one web attack in ten and a model detecting nineteen in twenty are separated by
0.3 percentage points of accuracy. Any evaluation, comparison or model-selection
procedure based on accuracy or weighted F1 cannot distinguish them. Macro-averaged
metrics, which weight every class equally, separate them clearly.

**The ensemble did not outperform its best member.** Soft voting averages predicted
probabilities across constituent models. Because two of the three constituents are
near-blind to WEBATTACK, their confident BENIGN predictions outvote the DNN's correct
one. The ensemble inherits the majority's weakness rather than the best member's
strength — a useful reminder that ensembling is not automatically beneficial when
members have correlated blind spots.

**Neural networks handled the imbalance better than tree ensembles here.** The
plausible mechanism is that gradient descent with class weighting applies a
continuous penalty for minority-class errors throughout training, whereas tree
splitting criteria are dominated by the majority classes when a minority represents
under 0.5% of samples. This observation is specific to this dataset and configuration
and is offered as an interpretation, not a general claim.

### 4.7.4 Model Selection Procedure

The above result has a direct engineering consequence. The training pipeline
originally selected the model to deploy by **weighted F1** — the one metric that
cannot distinguish these models. The selection procedure was therefore reformulated:

1. Any model whose **weakest per-class recall falls below 0.50** is **rejected**,
   whatever its aggregate score.
2. Remaining models are ranked by **macro F1**.
3. The choice, the rule and the per-class metrics of *every* candidate are written
   to `artifacts/manifest.json`, and the serving code reads that file rather than
   inferring the model from filenames.

Applying this procedure to the trained models:

```
Excluded (per-class recall < 50%):
    GradientBoosting     WEBATTACK = 0.10
    RandomForest         WEBATTACK = 0.08
    VotingEnsemble       WEBATTACK = 0.10

Selected: DNN (macro F1 = 0.9657, weakest class BOTNET = 0.74)
```

**[Insert Screenshot: Console output of the model selection procedure showing rejected models and the final selection]**

**[Insert Screenshot: Contents of `artifacts/manifest.json` showing served model, selection rule and per-class metrics]**

### 4.7.5 End-to-End Pipeline Behaviour

The table below shows the complete pipeline response to a representative flow of
each class — detection through to the authorised action:

| Input profile | Predicted | Confidence | Risk | Severity | Action taken | Approval |
|---|---|---|---|---|---|---|
| BENIGN | BENIGN | 0.99 | 0.0 | INFO | LOG_ONLY | auto |
| PORTSCAN | PORTSCAN | 1.00 | 40.0 | MEDIUM | RATE_LIMIT | auto |
| BRUTEFORCE | BRUTEFORCE | 1.00 | 70.0 | HIGH | NOTIFY_SOC | auto |
| DOS | DOS | 1.00 | 81.2 | CRITICAL | BLOCK_IP | auto |
| WEBATTACK | WEBATTACK | 0.97 | 87.1 | CRITICAL | BLOCK_IP | auto |
| DDOS | DDOS | 1.00 | 88.8 | CRITICAL | BLOCK_IP | auto |
| BOTNET | BOTNET | 1.00 | 95.0 | CRITICAL | BLOCK_IP | auto |

Two behaviours are worth noting.

**Graduated response.** Port scanning receives rate limiting rather than an IP block,
despite the model being 100% confident. Under the earlier confidence-only risk
formulation this flow scored 100 and triggered automatic blocking. Since scanning is
constant background noise on any internet-facing interface, automatically blocking
every scanner is self-harm. The revised scoring produces a response proportional to
consequence rather than to certainty.

**Independent corroboration.** The DDOS and DOS profiles show risk values above their
class base (88.8 against a base of 85; 81.2 against 75) because the unsupervised
anomaly layer independently flagged these flows as out-of-distribution. Agreement
between two independently trained models is stronger evidence than either alone.

**[Insert Screenshot: Simulation page showing a generated attack with its detection, decision and response outcome]**

**[Insert Screenshot: Live activity feed showing the real agent trace — detection_agent_started, ids_detection_completed, decision_agent_completed, response_agent_completed]**

---

## 4.8 Summary of Work

The implemented system comprises:

- A preprocessing pipeline reducing 2.5 million labelled flows to a balanced,
  42-feature training set.
- Four trained classifiers plus a two-model unsupervised anomaly layer.
- A six-agent orchestrated pipeline with policy-driven, guard-authorised response.
- A live ingestion path from packet capture through to detection.
- A REST API of 45 endpoints and a React operations dashboard.
- An automated suite of 446 tests.

The principal experimental finding is that **aggregate accuracy is an unsafe basis
for evaluating intrusion detection models on imbalanced data**. Four models within
0.3 percentage points of accuracy differ by a factor of twelve in their ability to
detect web attacks. Reporting macro-averaged metrics, and enforcing a minimum
per-class recall during model selection, are therefore not refinements but
requirements.

The principal engineering finding is that **the most dangerous defects in a security
platform are those that degrade it toward silence**. The feature-contract mismatch
described in Section 4.6.3 caused the detector to report a network clean with maximum
confidence while receiving no data, and no accuracy metric could have revealed it.
Contract testing at component boundaries, and refusing to predict on inputs that fail
a coverage check, address a class of failure that model evaluation cannot.

### Known Limitations

| Limitation | Description |
|---|---|
| No infiltration detection | The dataset contains no infiltration records; seven classes is the ceiling for this data. |
| BOTNET recall 0.74 | Approximately one in four command-and-control flows is missed, and C2 traffic implies an already-compromised host. |
| Simulated containment | Response executors maintain an in-process ledger; no firewall or endpoint integration is enabled. |
| Single-host memory | The embedded vector store permits one process at a time, limiting horizontal scaling. |
| Dataset-derived evaluation | Reported metrics come from CICIDS2017 held-out data. Performance on a specific production network requires validation on that network's traffic. |
