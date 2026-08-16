# Cyber Surakshya — SOC Operations Guide

**Audience:** SOC analysts and shift leads operating the platform day to day.
**Scope:** how to start it, how to read what it tells you, when to trust it, and when not to.

Every command, endpoint response and number in this guide was executed against a
running instance of this build. Where the platform's behaviour differs from older
docs, this guide reflects the running system.

---

## 1. What this platform is

Cyber Surakshya classifies **network flows** — not packets, not files, not logs.
A flow is one conversation between two hosts (source IP, source port, destination
IP, destination port, protocol) reduced to 42 numeric measurements: durations,
packet counts, byte counts, inter-arrival timings.

**The model never reads payload.** This has two consequences you should carry into
every triage decision:

- It works on encrypted traffic, because it never needed the plaintext.
- It cannot tell you *what* was in the session. It tells you the session's shape
  matches an attack class. Confirming content is your job, with other tooling.

Six agents process each flow in sequence, coordinated by a hub-and-spoke graph:

| Agent | Consumes | Produces |
|---|---|---|
| **Coordinator** | pending work queue | dispatch decisions |
| **Detection** | `SecurityEvent` | label, confidence, risk score |
| **Analysis** | `DetectionResult` | severity, evidence, summary |
| **Decision** | `AnalysisResult` | action + whether approval is required |
| **Response** | `DecisionResult` | executed / downgraded / refused |
| **Learning** | historical records | metrics, patterns, recommendations |

The Response agent reads **only** the decision — never the original flow. It can
refuse or downgrade an action, but it can never escalate one. That constraint is
structural, not a policy setting.

---

## 2. Starting the platform

### 2.1 Prerequisites check

The repository ships with trained artifacts and an installed frontend. You do
**not** need to retrain to operate.

```bash
cd /c/Users/ACER/Downloads/files
ls artifacts/          # must contain model_DNN.pkl, scaler.pkl, label_encoder.pkl,
                       # feature_columns.json, manifest.json, anomaly_thresholds.json
```

Two `.env` files must exist and **their keys must match**:

| File | Variable |
|---|---|
| `.env` | `CYBER_SURAKSHYA_API_KEY=<value>` |
| `frontend/.env` | `VITE_API_KEY=<same value>` |

`frontend/.env` also needs `VITE_API_BASE_URL=http://localhost:8000`.

If you need to generate a fresh key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

The backend **refuses to start** without `CYBER_SURAKSHYA_API_KEY`. That is
deliberate — an unauthenticated SOC console is worse than no console.

### 2.2 Terminal 1 — backend

```bash
.venv/Scripts/python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000
```

**Expect a slow first start.** The memory layer pulls in `sentence-transformers`
and torch; the process sits near 500 MB of RSS producing no log output for
several seconds before it binds the port. On the verified run it answered
`/health` **11 seconds** after launch. Silence during that window is normal —
do not kill and retry.

Add `--reload` only for development. In a live shift it restarts the process
mid-investigation.

### 2.3 Terminal 2 — frontend

```bash
cd frontend
npm run dev
```

Vite reports ready in about 4 seconds and serves on **http://localhost:5173**.
It also prints LAN addresses; ignore them unless you intend the console reachable
from other machines, which requires widening the backend CORS list in
[app.py:84-94](app.py#L84-L94).

### 2.4 Confirm the platform can actually detect

This is the step that matters. `/health` does not merely check the process is
alive — it **scores a real flow through the served model**. A 200 means the
model, the scaler and the label encoder all agree with each other.

```bash
curl http://127.0.0.1:8000/health
```

Verified healthy response:

```json
{
  "status": "ok",
  "runtime": true,
  "artifacts_loaded": true,
  "detector": "ok",
  "anomaly_layer": "active",
  "classes": ["BENIGN","BOTNET","BRUTEFORCE","DDOS","DOS","PORTSCAN","WEBATTACK"],
  "feature_count": 42,
  "model": {
    "type": "MLPClassifier",
    "served": "model_DNN.pkl",
    "selection_rule": "highest macro recall among models with per-class recall >= 50%",
    "f1_macro": 0.9657,
    "recall_macro": 0.9543,
    "weakest_class": "BOTNET",
    "weakest_recall": 0.74
  },
  "memory": { "available": true, "provider": "QdrantSqliteMemoryProvider" },
  "probe_label": "BENIGN"
}
```

**Read these four fields every shift start:**

- `detector: "ok"` — the model scored the probe flow.
- `anomaly_layer: "active"` — the second opinion is running. If this is inactive,
  you lose novel-attack detection and every `INCONCLUSIVE` verdict with it.
- `feature_count: 42` — the feature contract is intact.
- `memory.available: true` — repeat-offender correlation works. If false,
  `/learning/*` and `/alerts` return 503 and Decision Rule 2 can never fire.

A **503 means detection is disabled**, with the reason in the body. The platform
fails closed. It will not run with a missing or mismatched model, and it will not
quietly serve a degraded detector.

### 2.5 Verified service map

| Service | URL | Auth |
|---|---|---|
| SOC console | http://localhost:5173 | key injected from `frontend/.env` |
| API | http://127.0.0.1:8000 | `X-API-Key` header |
| Swagger / interactive API docs | http://127.0.0.1:8000/docs | — |
| Prometheus metrics | http://127.0.0.1:8000/metrics | public |
| Live agent event stream (SSE) | http://127.0.0.1:8000/feed | public |

Requests without the key return **401**. (Older docs say 403; the running build
returns 401.)

---

## 3. The console — page by page

Eleven routes, defined in [frontend/src/routes/router.jsx](frontend/src/routes/router.jsx).

| Page | Route | What you do here |
|---|---|---|
| **Dashboard** | `/` | Shift overview: alert counts, severity split, attack-type mix, trend |
| **Live Capture** | `/live` | Start/stop the network tap; watch flow counters and preflight |
| **Alerts** | `/alerts` | The triage queue. Filter, search, sort |
| **Alert Detail** | `/alerts/:id` | Full chain for one alert — the primary investigation view |
| **Response** | `/response` | Executed actions, guard verdicts, **pending approvals** |
| **Learning** | `/learning` | Platform metrics, discovered patterns, recommendations, feedback |
| **Agents** | `/agents` | Per-agent health and throughput |
| **Blocked IPs** | `/blocked` | The containment ledger |
| **Blocked IP Detail** | `/blocked/:id` | Why one IP was blocked, and by which decision |
| **Simulation** | `/simulation` | Generate a synthetic attack end to end — training and validation |
| **Memory** | `/memory` | Historical correlation store |
| **Settings** | `/settings` | Local console configuration |

### The two pages that need attention every shift

**`/response` → Pending Approvals.** Any action the Decision agent marked
`requires_approval` waits here and **nothing happens until a human acts**. Host
isolation on a repeat offender is the common case. An unattended queue here means
containment that everyone assumed had happened, has not.

**`/live`.** Capture is **off by default** and stays off across restarts.
Starting a packet capture is a privileged act, so the platform requires an
explicit operator decision every time.

---

## 4. How to read an alert

### 4.1 The chain

Open `/alerts/:id`. You are looking at four linked records. Read them in order —
each one constrains the next.

A verified end-to-end run (`POST /simulation/simulate-attack`):

```
DETECTION   BOTNET, confidence 100%, risk 95.0
ANALYSIS    severity CRITICAL
            "Detection BOTNET is detected with 100.00% confidence,
             CRITICAL severity, and risk score 95.00."
DECISION    BLOCK_IP, priority CRITICAL, requires_approval: false
            "CRITICAL severity with risk score 95/100. Automated inline
             containment is warranted without analyst approval."
RESPONSE    EXECUTED, guard verdict ALLOW, rule "authorised"
            trust tier DETERMINISTIC, executor SimulatedContainmentExecutor
LEDGER      151.49.116.239 blocked
```

The **guard verdict** is the field analysts most often skip and most need. It
tells you whether what the Decision agent *asked for* is what actually *happened*.
`ALLOW` means they match. Anything else means they do not — see §6.

### 4.2 Detection status — three values, not two

| Status | Meaning | Your action |
|---|---|---|
| `BENIGN` | classifier says normal, anomaly layer agrees | logged, no action |
| `DETECTED` | classifier identified an attack class above threshold | triage by severity |
| `INCONCLUSIVE` | **the two layers disagree** | manual review — this is the interesting one |

`INCONCLUSIVE` is the entire reason a second model exists. A supervised classifier
can only choose among classes it has seen, so a genuinely novel attack gets
confidently filed under the nearest known class — possibly BENIGN. When the
unsupervised layer flags a flow the classifier called benign, the platform reports
**uncertain** rather than **safe**.

**Treat `INCONCLUSIVE` as a lead, not as noise.** It is the only signal this
platform produces for attacks it was never trained on.

### 4.3 Risk score — consequence, not certainty

```
risk = base_risk(predicted_class) × confidence
```

with an upward adjustment when the anomaly layer independently agrees.

| Class | Base risk | Why |
|---|---|---|
| BOTNET | 95 | C2 traffic implies the host is **already compromised** |
| WEBATTACK | 90 | SQLi/XSS are direct data-breach vectors |
| DDOS | 85 | Availability impact, no compromise implied |
| DOS | 75 | Availability impact, smaller blast radius |
| BRUTEFORCE | 70 | Credential attack, noisy, often unsuccessful |
| PORTSCAN | 40 | Reconnaissance only; constant background noise |
| *unknown class* | 60 | Mid-range default for a retrained model |

This matters for how you prioritise. A port scan at 100% confidence scores **40**,
not 100. The model being certain is not the same as the event being important.
An earlier build scored risk as `confidence × 100`, which pushed essentially every
detection above 80 and auto-blocked routine scanners — self-harm on any
internet-facing interface.

**Severity bands** ([cyber_surakshya/platform/risk/score.py:14-18](cyber_surakshya/platform/risk/score.py#L14-L18)):

| Risk | Level |
|---|---|
| 0 – 19.99 | NEGLIGIBLE |
| 20 – 39.99 | LOW |
| 40 – 59.99 | MODERATE |
| 60 – 79.99 | HIGH |
| 80 – 100 | CRITICAL |

### 4.4 Corroboration is a real signal

When you see risk *above* the class base — DDOS at 88.8 against a base of 85, DOS
at 81.2 against 75 — the unsupervised anomaly layer independently flagged that
flow as out-of-distribution. Two independently trained models agreeing is
materially stronger evidence than either alone. Weight it accordingly.

---

## 5. Decision policy — the seven rules

Evaluated **top to bottom, first match wins**
([agents/decision/deterministic.py:57-199](agents/decision/deterministic.py#L57-L199)).
Rules are pure data — thresholds only, no attack names in logic — so a new threat
needs no code change.

| # | Rule | Conditions | Action | Approval |
|---|---|---|---|---|
| 1 | `critical_high_risk_auto_block` | severity ≥ CRITICAL **and** risk ≥ 80 | `BLOCK_IP` | auto |
| 2 | `repeat_offender_isolate` | ≥ 2 prior incidents **and** status = DETECTED | `ISOLATE_HOST` | **required** |
| 3 | `high_confidence_detected_notify` | severity ≥ HIGH, confidence ≥ 0.75, DETECTED | `NOTIFY_SOC` | auto |
| 4 | `medium_severity_rate_limit` | severity ≥ MEDIUM, DETECTED | `RATE_LIMIT` | auto |
| 5 | `low_severity_detected_notify` | any remaining DETECTED | `NOTIFY_SOC` | auto |
| 6 | `inconclusive_soc_review` | status = INCONCLUSIVE | `NOTIFY_SOC` | auto |
| 7 | `benign_log_only` | status = BENIGN | `LOG_ONLY` | auto |

**Rule 2 is the only one that stops for a human**, and it requires
`DETECTED` — not just a memory hit. An earlier version matched on prior incidents
alone, which meant a *benign* flow from an IP with two old records proposed
isolating the host. A memory hit is not evidence of current malicious activity.

Expected pipeline behaviour by class, verified end to end:

| Profile | Predicted | Conf. | Risk | Severity | Action | Approval |
|---|---|---|---|---|---|---|
| BENIGN | BENIGN | 0.99 | 0.0 | INFO | `LOG_ONLY` | auto |
| PORTSCAN | PORTSCAN | 1.00 | 40.0 | MEDIUM | `RATE_LIMIT` | auto |
| BRUTEFORCE | BRUTEFORCE | 1.00 | 70.0 | HIGH | `NOTIFY_SOC` | auto |
| DOS | DOS | 1.00 | 81.2 | CRITICAL | `BLOCK_IP` | auto |
| WEBATTACK | WEBATTACK | 0.97 | 87.1 | CRITICAL | `BLOCK_IP` | auto |
| DDOS | DDOS | 1.00 | 88.8 | CRITICAL | `BLOCK_IP` | auto |
| BOTNET | BOTNET | 1.00 | 95.0 | CRITICAL | `BLOCK_IP` | auto |

---

## 6. Response authorisation — why an action may not be what was decided

Before anything executes, an `ActionGuard` evaluates it. Live policy from
`GET /response/policy`, sourced from
[config/response_policy.yaml](config/response_policy.yaml):

**Destructive actions** (require a trusted engine):
`BLOCK_IP`, `ISOLATE_HOST`, `QUARANTINE_FILE`, `RATE_LIMIT`,
`REVOKE_CREDENTIALS`, `TERMINATE_PROCESS`

**Engine trust tiers:**

| Tier | Destructive allowed | Min confidence |
|---|---|---|
| `DETERMINISTIC` | yes | 0.70 |
| `AI_SUPERVISED` | **no** | 0.90 |
| `AI_AUTONOMOUS` | yes (opt-in only) | 0.95 |
| `UNKNOWN` | no | 1.01 — unreachable, always downgrades |

Only `DeterministicDecisionEngine` is currently mapped to a tier. Any unlisted
engine resolves to `UNKNOWN` and is always downgraded, so wiring in a new decision
engine is necessarily an explicit, auditable act.

**Protected targets** — refused outright, regardless of engine or approval.
Loopback, link-local, multicast, broadcast, IPv6 equivalents, plus
**auto-detected** local host and gateway addresses. On the verified run the guard
had added `192.168.1.73/32` and `192.168.1.1/32` by itself. This is what stops the
platform from blackholing its own default route.

**Blast radius:**

| Control | Limit |
|---|---|
| Destructive actions per incident | 3 |
| Per-target window | 900 s |
| Global circuit breaker | 10 destructive actions/minute |

**Failed checks downgrade to `NOTIFY_SOC` — they are never silently dropped**, and
every verdict is recorded on the `ResponseResult`. If you see a decision of
`BLOCK_IP` with a response of `NOTIFY_SOC`, read `guard_rule` and `guard_reason`
on the alert detail page. The platform is telling you it refused, and why.

> **`dry_run: false` is set in the current config.** The global kill-switch is
> off, so authorised actions execute against their executor. See §9 for what
> "execute" currently means.

---

## 7. Live capture

**Capture is off by default. It never auto-starts.**

Current policy ([config/ingestion_policy.yaml](config/ingestion_policy.yaml)) —
verified from `GET /ingestion/status`:

| Setting | Value |
|---|---|
| Backend | `local_dumpcap` |
| Interface | `Wi-Fi` |
| Snaplen | **96 bytes — headers only** |
| BPF filter | none |
| Rotation | 60 s × 120 files = **2 h retention** |
| Output | `captures/` |
| Min free disk | 512 MB |
| Max total size | 4096 MB |

**Snaplen 96 is the single highest-value privacy control in the platform.** Every
flow feature is computable from headers, so payloads would write credentials,
tokens and personal data to disk for zero analytical gain. Do not raise it.

### Before you start capture

Always run preflight. It reports **every** blocker at once rather than failing one
at a time:

```bash
curl -H "X-API-Key: $KEY" http://127.0.0.1:8000/ingestion/preflight
```

Verified ready response:

```json
{"ready":true,"blockers":[],"warnings":[],
 "checks":{"capture_backend":true,"capture_policy":true,
           "stream":true,"normalizer":true,"runtime":true}}
```

All five checks must be `true`. `stream` requires Redis:

```bash
docker compose up -d redis
```

Then start from the `/live` page, or:

```bash
curl -X POST -H "X-API-Key: $KEY" http://127.0.0.1:8000/ingestion/start
```

The path is:

```
interface → dumpcap (headers only) → rotating .pcap
  → cicflowmeter → FlowNormalizer → Redis Streams
  → PipelineBridge → agent pipeline
```

Redis Streams sits in the middle deliberately: if the agent pipeline slows, flows
**queue rather than drop**, and an unacknowledged batch is redelivered after a
consumer crash. Silent flow loss is the one failure this layer must not have, so
it is configured `fail_closed: true` — it refuses to start when Redis is
unreachable rather than dropping traffic on the floor.

There is **no default interface**, by design. The platform must never guess which
network to tap.

### When the traffic is on another machine

The network worth watching is often not the one running the dashboard. Remote
mode taps nothing locally and instead accepts closed pcaps from sensors
elsewhere, which join the pipeline at exactly the point a local capture file
would — same flow extraction, same agents, same alerts.

On the `/live` page pick **Remote sensors (submitted pcaps)** from the interface
dropdown, or:

```bash
curl -H "X-API-Key: $KEY" "http://127.0.0.1:8000/ingestion/preflight?mode=remote"
curl -X POST -H "X-API-Key: $KEY" "http://127.0.0.1:8000/ingestion/start?mode=remote"
```

Remote preflight drops `capture_backend` and `capture_policy` and adds
`upload_policy` — a host with no dumpcap and no interface can still ingest
everything its sensors send it.

Then, on each sensor host:

```bash
dumpcap -i eth0 -s 96 -b duration:60 -b files:2 -w /tmp/sensor.pcap

curl -X POST http://<platform-host>:8000/ingestion/pcap \
     -H "X-API-Key: $KEY" \
     -F "file=@/tmp/sensor_00001.pcap"
```

The response is the result, not an ack — it reports how many flows that file
contributed. Refusals are actionable: **409** nobody is listening (go live in
remote mode), **413** over the 256 MB ceiling (rotate smaller), **415** not a
pcap, **422** unreadable — do not retry it unchanged.

Two behaviours worth knowing before you rely on it:

- **Identical bytes are ingested once.** Files are stored under a hash of their
  own content, so a sensor retrying a timed-out upload gets `duplicate: true`
  and publishes nothing. Without this, a retry loop would fabricate a
  volumetric attack out of one honest capture.
- **A submission is traffic the platform did not witness.** Flows carry the
  sender's addresses, and anything holding the API key can submit. There is no
  per-sensor identity and no rate limit — attribution in the resulting alerts
  is only as trustworthy as the sensor. Watch the `uploads` counters in
  `/ingestion/status`: `rejected` and `failed` climbing means a misconfigured
  or hostile sender, which otherwise looks exactly like a quiet network.

---

## 8. Learning loop and analyst feedback

Your dispositions are the training signal. `GET /learning/metrics` on the verified
run:

```json
{"total_incidents":469,"labeled_incidents":3,"feedback_coverage":0.0064,
 "min_sample_size":10,
 "metrics":[{"name":"pipeline_completion_rate","value":0.9531,
             "detail":"447 of 469 incident(s) traversed every stage"}]}
```

**`feedback_coverage` of 0.6% is the number to act on.** Only 3 of 469 incidents
carry an analyst verdict, and `min_sample_size` is 10 — so most learning metrics
cannot yet reach a conclusion. The platform is honest about this rather than
reporting confident statistics from three samples, but it means the learning layer
is effectively idle until analysts label more.

Submit a disposition when you close an alert:

```bash
curl -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"alert_id":"<id>","label":"TRUE_POSITIVE","notes":"confirmed C2 beacon"}' \
  http://127.0.0.1:8000/learning/feedback
```

Then `POST /learning/analyze` regenerates patterns and recommendations. The
Learning agent is deliberately **not** a pipeline node — it works over accumulated
history, so running it per-flow would re-derive platform-wide metrics on every
packet. Run it on demand, typically end of shift.

---

## 9. Limits you must know before you trust a verdict

| Limitation | Operational consequence |
|---|---|
| **Containment is simulated** | `SimulatedContainmentExecutor` writes to an **in-process ledger**. No firewall, no EDR. A "blocked" IP on `/blocked` is **not blocked on your network.** Someone must act on it. |
| **BOTNET recall 0.74** | Roughly **one in four C2 flows is missed** — and C2 implies an already-compromised host. Do not treat a quiet BOTNET count as an all-clear. |
| **No INFILTRATION class** | The training data contains zero infiltration rows. Infiltration and lateral movement are **invisible** to this platform regardless of model quality. |
| **Seven classes only** | Anything outside them can only ever surface as `INCONCLUSIVE` via the anomaly layer. |
| **Memory is single-writer** | Embedded Qdrant permits one process. A second backend makes `/learning/*` and `/alerts` return 503. |
| **No LLM engine** | The `AI_SUPERVISED` tier exists but no engine is wired. All decisions are deterministic rules. |
| **Metrics are dataset-derived** | Performance figures come from held-out CICIDS2017. Your network's real false-positive rate must be measured on your network. |

**The most important line in this table is the first one.** The platform decides
and records containment; it does not enforce it. Wiring a real executor is a
startup change, not a config toggle.

### Why the served model is the DNN

Four models were trained. Three of them — RandomForest, GradientBoosting and
VotingEnsemble — score **above 0.99 weighted F1 while catching 8–10% of
WEBATTACK**. The served DNN catches **95%**.

Accuracy cannot tell them apart, because BENIGN/DDOS/DOS/PORTSCAN are ~99% of
rows. **Quote macro F1 (0.9657), never accuracy.** If anyone reports this system's
performance as "99% accurate", that number is true and useless.

`artifacts/manifest.json` records the selection and `inference.resolve_model_path`
honours it, so dropping in a `model.pkl` built from the wrong estimator can no
longer silently blind the detector.

---

## 10. API quick reference

```bash
KEY=$(grep '^CYBER_SURAKSHYA_API_KEY=' .env | cut -d= -f2- | tr -d '\r\n "')
```

**Public — no key:**

| Endpoint | Purpose |
|---|---|
| `GET /health` | Scores a real flow. 503 = detection disabled |
| `GET /metrics` | Prometheus exposition |
| `GET /feed` | SSE stream of real agent events |
| `GET /feed/recent` | Last N events, for a console that just loaded |

**Authenticated** — send `-H "X-API-Key: $KEY"`:

| Endpoint | Purpose |
|---|---|
| `GET /stats` | Dashboard rollup |
| `GET /alerts`, `/alerts/{id}`, `/alerts/{id}/detail` | Triage queue and full chain |
| `DELETE /alerts/{id}` | Dismiss |
| `GET /analyses`, `/analyses/{id}` | Analysis records |
| `GET /agents`, `/agents/status` | Agent health |
| `GET /response/actions`, `/response/actions/{id}` | Action audit trail |
| `GET /response/pending-approvals` | **The human-decision queue** |
| `POST /response/actions/{decision_id}/approve` | Authorise |
| `POST /response/actions/{decision_id}/reject` | Refuse |
| `GET /response/policy` | Live guard configuration |
| `GET /blocked-ips`, `DELETE /blocked-ips/{id}` | Containment ledger |
| `GET /ingestion/preflight`, `/status`, `/interfaces` | Capture readiness (`?mode=remote` for remote) |
| `POST /ingestion/start`, `/stop` | Capture control (`?mode=remote` to accept submissions) |
| `POST /ingestion/pcap` | Submit a pcap from a remote sensor |
| `POST /predict`, `/predict/csv`, `/predict/zeek` | Direct model scoring |
| `POST /simulation/simulate-attack` | Full pipeline exercise |
| `POST /simulation/upload-zeek` | Score a `conn.log` |
| `GET /learning/metrics`, `/patterns`, `/recommendations`, `/report(s)` | Learning outputs |
| `POST /learning/feedback`, `/learning/analyze` | Submit disposition, regenerate |
| `GET /debug/memory` | Memory store diagnostics |

Full interactive reference: **http://127.0.0.1:8000/docs**

### Shift-start check, one paste

```bash
KEY=$(grep '^CYBER_SURAKSHYA_API_KEY=' .env | cut -d= -f2- | tr -d '\r\n "')
curl -s http://127.0.0.1:8000/health | python -m json.tool | head -20
curl -s -H "X-API-Key: $KEY" http://127.0.0.1:8000/agents/status
curl -s -H "X-API-Key: $KEY" http://127.0.0.1:8000/response/pending-approvals
curl -s -H "X-API-Key: $KEY" http://127.0.0.1:8000/ingestion/status
```

Healthy baseline: `agents/status` reports `{"status":"online","active_agents":6,
"total_agents":6}`.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Backend exits instantly at startup | `CYBER_SURAKSHYA_API_KEY` unset | Set it in `.env`; the refusal is deliberate |
| No log output for ~10 s on start | torch / sentence-transformers loading | Normal. Wait for the port to bind |
| Console loads, every panel empty | Key mismatch between `.env` and `frontend/.env` | Make them identical, restart **both** |
| API returns 401 | Missing or wrong `X-API-Key` | Send the header; only `/health`, `/metrics`, `/feed*` are public |
| `/health` returns 503 | Model/scaler/encoder mismatch | Read the body. Do not "fix" by swapping a `.pkl` — regenerate `manifest.json` |
| `/alerts` and `/learning/*` return 503 | Second process holding embedded Qdrant | Single writer only. Stop the other backend |
| Capture will not start | Preflight blocker | `GET /ingestion/preflight` lists every blocker at once |
| `preflight.stream: false` | Redis down or unauthenticated | `docker compose up -d redis`; check `INGESTION_REDIS_*` in `.env` |
| Redis "Authentication required" while Redis looks healthy | Credentials not loaded into the server's environment | `app.py` loads `.env` at import — start the server from the project root |
| Every flow scored BENIGN at exactly 1.000 confidence | **Feature contract broken** — see below | Stop and investigate |

### The failure mode worth memorising

Zero variance in confidence across thousands of distinct flows is **the signature
of a constant input vector**, not of a genuinely clean network.

This platform has been bitten by it. A naming and unit mismatch between the
capture tool and the model (`snake_case` vs `Title Case`; seconds vs microseconds)
meant **0 of 42 features matched**. Unmatched features are zero-filled, so the
detector confidently reported 5,155 real flows as BENIGN at 1.000 confidence while
receiving no information at all — and **every accuracy metric stayed at 99%**,
because those metrics are computed on the dataset, not on live traffic.

A coverage guard now raises an error when an input matches fewer than half the
expected features. But if you ever see a flat 1.000 confidence across a varied
traffic sample, treat the detector as **blind until proven otherwise**. A security
tool degrading toward silence is the most dangerous defect it can have, because it
looks exactly like good news.

---

## 12. Shutting down

`Ctrl+C` in each terminal. The backend's lifespan handler releases the Qdrant
client and stops any running capture on the way out — a capture must not outlive
the server that started it.

Verify nothing is left holding the port or the memory store:

```powershell
Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
```
