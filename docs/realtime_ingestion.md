# Real-Time Ingestion

> **Status: Phases 0-4 complete.** Phase 5 (throughput + live source) is planned in `docs/plans/realtime_ingestion_plan.md`.
>
> - **Phase 0 — the feature contract.** cicflowmeter output reaches the model correctly.
> - **Phase 1 — capture.** Rotating, snaplen-limited, retention-bounded pcap capture.
> - **Phase 2 — stream.** Durable Redis Streams transport that loses nothing and replays nothing.
> - **Phase 3 — bridge.** Captured packets reach the six-agent pipeline.
> - **Phase 4 — control plane.** Authenticated Go Live, fail-closed, with visible backlog.

## Why Phase 0 blocked everything else

Before this milestone, the vendored Python cicflowmeter and the CICIDS2017-trained model could not talk to each other, and the failure was silent in both directions.

```
model features (artifacts/feature_columns.json) : 42
mapped from cicflowmeter output                 : 0     ← before
                                                : 42    ← after
```

Had the capture and streaming layers been built first, the pipeline would have run end to end, the dashboard would have filled with alerts, and every prediction would have been meaningless.

## The two mismatches

### 1. Naming

cicflowmeter emits snake_case (`flow_duration`, `tot_fwd_pkts`); the model expects CICIDS2017 Title Case (`Flow Duration`, `Total Fwd Packets`). `inference.CICFLOW_ALIASES` covers only the **Java** CICFlowMeter spelling (space-prefixed Title Case), so it maps nothing from the Python tool. `FEATURE_SOURCE_MAP` in `ingestion/flows/normalizer.py` provides the complete 42-entry mapping.

### 2. Units — the dangerous one

CICIDS2017 expresses durations and inter-arrival times in **microseconds**. The Python cicflowmeter emits **seconds**.

| | value |
|---|---|
| `flow_duration` in `out.csv` | median `0.00097`, max `10.48` |
| `Flow Duration` in the platform's CICIDS2017 attack profiles | `50`, `30000000`, `3600000000` |

A rename-only mapping feeds the model values **10⁶ times too small**. It does not raise — it returns confident, plausible labels.

**Demonstrated, not asserted.** Running the platform's own attack profiles through the model with and without the conversion:

| profile | correct units | unit bug |
|---|---|---|
| SYN_Flood_DDoS | DOS | DOS |
| SSH_BruteForce | DOS | DOS |
| PortScan | BENIGN | BENIGN |
| DoS_Hulk | DDOS | DDOS |
| **Botnet_C2** | **PORTSCAN** | **DDOS** ← flipped |
| Normal_HTTP_GET | BENIGN | BENIGN |

One in six profiles is misclassified by the unit bug alone. On the two real captures available (`out.csv`, `malware_c2.pcap`) labels did **not** change — the corruption is real and provable, but it is a distortion rather than a total collapse. Both facts are worth holding: the fix is necessary, and it is not the only thing standing between this platform and accurate live detection (see *Known limitations*).

**13 of 42 features need ×1 000 000**, and **4 are per-second rates that must never be scaled**. Both sets are enumerated explicitly in the normalizer rather than inferred from name patterns — `Flow Bytes/s` contains no time word and `Idle Mean` contains no `IAT`, so any heuristic gets at least one wrong. Scaling a rate by mistake is the same bug with the sign flipped.

## The corrupted artifact

`artifacts/feature_columns.json` contained `"pyDestination Port"` at index 25.

**This was not an editing accident in the JSON.** The typo originates in the training dataset itself: the first column of `data/cicids2017_cleaned.csv` is literally named `pyDestination Port`. `preprocess.py` derives the selected-feature list from that header (`select_features` reads `df.columns`), so the corrupted name was faithfully carried into the artifact and into `artifacts/evaluation_report.txt:116`.

The column holds **genuine destination-port values** — verified two ways:

* Sampled values are ports (`22`, `35396`, `52320`, `60058`).
* The fitted scaler statistics at index 25 are `mean=4306.3`, `scale=12838.7` — a destination-port distribution, not a garbage column.

So the model was trained on real destination ports under a misspelled name.

Because the scaler is **positional** (`n_features_in_=42`, `feature_names_in_=None`), training and inference were unaffected; only name-based selection broke — which is exactly what live ingestion does. The fix was an index-preserving rename, verified by hashing model output on a fixed input before and after:

```
baseline  scaled f3fffafb09b9ee44 | pred [4, 4, 4, 5, 4] | proba 87c7acf66596fd28
after     scaled f3fffafb09b9ee44 | pred [4, 4, 4, 5, 4] | proba 87c7acf66596fd28
```

Byte-identical. No retraining, no reordering.

## What Phase 0 delivers

```
ingestion/
├── __init__.py
├── exceptions.py                 # FeatureContractError, UnmappedFeatureError
└── flows/
    ├── __init__.py
    └── normalizer.py             # FEATURE_SOURCE_MAP, FlowNormalizer, NormalizedFlow

tests/ingestion/
├── test_flow_normalizer.py       # 22 tests
└── fixtures/cicflowmeter_sample.csv   # real cicflowmeter output, 9 flows × 82 cols
```

### Design decisions

**Strict by default.** A flow missing a required column is **refused**, not zero-filled. A fabricated feature yields a confident wrong detection that nothing downstream can catch — not the analyst, not `LearningAgent`. `strict=False` exists for tolerant batch replay, and every fill is counted and attached to the flow as a warning.

**The source schema is validated once**, at startup, via `validate_source_columns()` — not per flow.

**The feature list is loaded from the artifact**, not hardcoded, so retraining with a different feature set raises `UnmappedFeatureError` at construction instead of silently mismatching at inference.

**Non-finite rates are clamped, not zeroed.** A single-packet flow has zero duration, so bytes/s is undefined. Zeroing would erase the extreme-rate signal that distinguishes a port scan from an idle connection. Training replaced `inf` with a median, so either choice is out of distribution; clamping at least preserves direction. Counted in `stats.non_finite_clamped`.

**`flow_id` is a deterministic hash of the five-tuple plus timestamp**, so replaying a pcap dedups instead of fabricating a volumetric attack — the platform deliberately treats repeated identical flows as signal.

## Usage

```python
import pandas as pd
from ingestion import FlowNormalizer

normalizer = FlowNormalizer()
frame = pd.read_csv("cicflowmeter_output.csv")

normalizer.validate_source_columns(frame.columns)   # once, at startup
flows = normalizer.normalize_frame(frame)

vector = flows[0].feature_vector(normalizer.feature_order)   # model-ready, 42 floats
print(flows[0].source_ip, flows[0].destination_port, flows[0].flow_id[:12])
```

## Known limitations (carried into later phases)

- **The model classified all 5 166 flows from `malware_c2.pcap` as BENIGN.** That is a generalization gap between CICIDS2017 and real traffic, not a normalizer fault — but it means live detection quality is unproven, and it is precisely what the analyst feedback loop (`POST /learning/feedback`) exists to measure. Do not read a working pipeline as a working detector.
- **Attack profiles classify imprecisely even with correct units** — `SSH_BruteForce` → `DOS`, `Botnet_C2` → `PORTSCAN`, `PortScan` → `BENIGN`. Labels are directionally useful, not exact.
- **`EXPIRED_UPDATE = 240`** in cicflowmeter means an idle flow is not emitted for up to 4 minutes, which will dominate MTTD for beaconing traffic regardless of transport.

## Bugs found in vendored cicflowmeter

Not fixed here — the package is third-party and untouched — but they will affect Phases 1–3:

1. `writer.py::HttpWriter.write` references `self.logger`, which the class never defines. Any POST failure raises `AttributeError` from inside the exception handler, masking the real error. Sits on the `-u/--url` path.
2. `writer.py::CSVWriter.__del__` assumes `__init__` succeeded. A bad output path surfaces as `AttributeError: 'CSVWriter' object has no attribute 'file'` instead of the actual `FileNotFoundError` — encountered while producing the test fixture.

## Running the tests

```bash
pytest tests/ingestion -v
```

---

# Phase 1 — Capture

Rotating pcap capture with a bounded retention window, minimum privilege, and headers-only recording.

## The platform constraint that shaped this phase

The plan called for a Docker container running dumpcap with `--net=host`. That is correct **on a Linux host** and meaningless on this development machine.

Docker Desktop runs the engine inside a Linux VM. A container's `--net=host` joins **that VM's** network namespace, not the laptop's Wi-Fi. A capture started that way does not fail — it succeeds against the wrong network, recording only container traffic while every health check reads green. It is the same class of silent-wrong-data failure as the Phase 0 unit bug.

So capture is **backend-pluggable**, with both backends producing byte-identical output into the same directory:

| Backend | Runs | Use |
|---|---|---|
| `LocalDumpcapBackend` | host `dumpcap` binary | Windows/macOS development — sees the real Wi-Fi/Ethernet |
| `DockerDumpcapBackend` | container, `--net=host` | Linux hosts, where that flag means what it reads like |

`DockerDumpcapBackend` **refuses to start when it detects Docker Desktop** rather than tapping the wrong thing, and `CaptureSession` substitutes the local backend with a recorded warning — never silently.

Verified on this host: Docker CLI 29.4.3 present, daemon not running; `dumpcap` 4.6.7 with Npcap present and able to enumerate real interfaces.

## What Phase 1 delivers

```
ingestion/
├── config.py                       # IngestionPolicy — YAML-backed, fail-closed
└── capture/
    ├── session.py                  # CaptureSession: start / stop / status / ready_files
    ├── retention.py                # sweeper behind dumpcap's ring buffer
    └── backends/
        ├── base.py                 # CaptureBackend ABC + shared dumpcap args
        ├── local_dumpcap.py        # host process
        └── docker_dumpcap.py       # container

config/ingestion_policy.yaml        # interface, snaplen, BPF, rotation, retention
docker/capture/Dockerfile           # alpine + dumpcap, non-root, capability-scoped
```

## Configuration

`config/ingestion_policy.yaml`, per the answers given for this deployment:

```yaml
capture:
  backend: local
  interface: "Wi-Fi"      # no default — see below
  snaplen: 96             # headers only
  rotate_seconds: 60
  retain_files: 120       # 60 × 120 = 2 hours
```

### There is no default interface

Every other setting has a safe fallback. `capture.interface` does not, and `validate_for_start()` refuses to run without it.

A wrong snaplen produces visibly degraded features. A wrong **interface** produces a perfectly healthy pipeline watching a network nobody asked about — and nothing downstream can tell. The platform must never guess which network to tap.

Interfaces resolve by friendly name (`"Wi-Fi"`), index (`"5"`), or device path (`\Device\NPF_{...}`); an unknown name fails at start with the list of valid options rather than capturing nothing.

## Security controls, verified

| Control | Verification |
|---|---|
| **snaplen 96** | Captured 35 packets on loopback; **maximum captured length exactly 96 bytes**. Payloads never reach disk. |
| **No `--privileged`** | The Dockerfile uses `setcap cap_net_raw,cap_net_admin=eip`; the runner passes `--cap-drop ALL` plus exactly those two. |
| **Non-root** | Image runs as `pcap`; `dumpcap` is `chmod 750`, `chown root:pcap`. |
| **Read-only rootfs** | `--read-only --tmpfs /tmp`; only `/captures` is writable. |
| **No shell in the container** | `ENTRYPOINT ["/usr/bin/dumpcap"]`, exec form — a crafted argument cannot become a shell command. GUI and dissector binaries are removed at build. |
| **BPF filter at capture time** | `-f` is applied in the kernel, before packets reach userspace or disk. |
| **Payload warning** | A snaplen above 256 raises an explicit warning naming credentials and PII — an operator may need payloads, but never by accident. |
| **Disk guard** | Start is refused below `min_free_disk_mb`; a capture that fills the disk takes the platform down with it. |
| **Capture artifacts gitignored** | `captures/`, `*.pcap`, `*.pcapng`. Even at snaplen 96 a pcap is a record of who talked to whom. |

## Retention

`dumpcap -b duration:60 -b files:120` gives the 2-hour window natively — no cron job, and a guarantee that file *k* is closed once file *k+1* exists.

The sweeper in `retention.py` is a **second line of defence**, because the ring buffer bounds a single dumpcap *run*, not the directory. A crash-restart leaves the previous ring behind and a changed `file_prefix` orphans everything written under the old one; two or three restarts turn a "2 hour" directory into a day of untracked traffic. The sweeper enforces both an age window and a total-size ceiling, oldest-first, and **never deletes the file being written**.

## The active-file rule

`CaptureSession.ready_files()` returns closed files only, always excluding the newest. Reading a pcap dumpcap still holds open yields a truncated final packet and a corrupt final flow. Phase 3 consumes this list, never the directory directly.

## Verified end to end

A bounded loopback capture — deliberately not the Wi-Fi — with 2-second rotation:

```
t= 2.2s files=2 ready=1 active=cs_00002_20260802011231.pcap
t= 4.4s files=3 ready=2 active=cs_00003_20260802011233.pcap
t= 6.6s files=4 ready=3 active=cs_00005_20260802011237.pcap
t= 8.8s files=4 ready=3 active=cs_00006_20260802011239.pcap   ← ring recycling at 4
```

And the full chain, Phase 1 into Phase 0:

```
1. CAPTURE   : 3 closed pcap(s) ready, active file excluded
2. CICFLOW   : 16 flow(s), 82 columns
3. NORMALIZE : 16 flow(s) -> 42/42 features, rejected=0
4. MODEL     : (16, 42) finite=True -> BENIGN=16
```

## Usage

```python
from ingestion.capture import CaptureSession

session = CaptureSession()               # loads config/ingestion_policy.yaml
print(session.list_interfaces())         # for the frontend's picker

session.start()
print(session.status().to_dict())
for pcap in session.ready_files():       # closed files only
    ...
session.sweep_retention()
session.stop()
```

## Deploying the container backend (Linux only)

```bash
docker build -t cyber-surakshya/capture:latest docker/capture
# then set capture.backend: docker and capture.interface: eth0
```

## Not yet wired

`CaptureSession` is complete but has **no API route** — starting a packet capture is a privileged operation and belongs behind the authenticated control plane in Phase 4, alongside "Go Live". Nothing starts a capture today except an explicit call.

---

# Phase 2 — Stream

A bounded, durable Redis Streams transport between capture and the agent pipeline.

## What Redis Streams is for here — and what it is not

It provides durability across a consumer restart, consumer groups with pending-entry recovery, replay from an offset, and natural backpressure through a bounded stream. All correct reasons to choose it.

It is **not a security control.** Redis binds to every interface with no authentication by default, and this stream carries a complete record of who talked to whom on the monitored network — an open instance leaks precisely what the platform exists to protect. Security comes from `docker/redis/`, not from the choice of transport.

## What Phase 2 delivers

```
ingestion/stream/
├── client.py            # connection, posture warnings, health snapshot
├── producer.py          # XADD + MAXLEN + flow_id dedup
└── consumer.py          # consumer group, ack, XAUTOCLAIM recovery, dead letter

docker/redis/redis.conf  # loopback, ACL file, noeviction, dangerous commands removed
docker/redis/users.acl   # per-role least privilege
docker-compose.yml       # redis service (+ capture behind a profile)
```

## The two guarantees

### Lose nothing

A message is acknowledged **only after** the caller confirms it was processed. A consumer that dies mid-batch leaves its messages pending, and another consumer reclaims them through `XAUTOCLAIM`. Tested by delivering to `worker-dead`, never acking, and asserting `worker-rescuer` recovers the flow.

`read_with_recovery()` reclaims stalled work **before** reading new work: an abandoned message is older than anything newly arrived, and processing it late beats never.

### Replay nothing

Acknowledged messages are never redelivered, and a consumer group never delivers the same entry to two consumers. The narrow window where a crash lands between processing and ack is covered by producer-side `flow_id` deduplication (`SET NX EX` — the check and the claim are one atomic operation, so two producers racing on the same flow cannot both win).

Verified end to end: publishing a 16-flow batch, then republishing the identical batch, yields **16 published and 0 on replay**. Without this, replaying a pcap would fabricate a volumetric attack — the platform deliberately treats repeated identical flows as signal.

## Poison messages

A flow that fails every attempt must not wedge the pipeline behind it; that would turn a parsing bug into a total detection outage. Two mechanisms:

- **Malformed entries are acknowledged immediately.** Redelivering something that cannot be parsed retries the same failure forever. Counted in `stats.malformed`.
- **Repeatedly-failing entries are dead-lettered** after `max_delivery_attempts` and moved to `cs:flows:dead` with the reason and original message ID attached. Preserved for inspection, never discarded — the platform does not drop evidence silently.

Retries increment through **reclaim**, not re-reads: `XREADGROUP` with `>` yields only new messages, so a pending entry's delivery counter advances via `XAUTOCLAIM`. The tests model that path rather than an idealised one.

## Backpressure

`XADD ... MAXLEN ~ 100000` bounds the stream so a traffic burst cannot exhaust Redis memory. Redis trims **silently**, so `backlog_ratio()` is the only warning a consumer gets that flows are about to be lost — surfaced in the health snapshot for the control plane.

`maxmemory-policy noeviction` in `redis.conf` is deliberate: a refused write is visible, an evicted stream entry is not.

## Fail closed

An unreachable Redis **refuses to start** rather than accepting flows and discarding them. A dropped flow is an attack the platform never saw and never reported — the one failure this layer must not have. `fail_closed: false` exists for development but is not the default.

One inversion: a **dedup** failure does not drop the flow. Losing a flow is worse than processing one twice, and the consumer is idempotent anyway.

## Security

### Credentials never live in the config file

`config/ingestion_policy.yaml` names the environment variables (`INGESTION_REDIS_USERNAME`, `INGESTION_REDIS_PASSWORD`); it never holds the values. A password in a committed file is a password in the repository history forever.

### Least privilege per role — `docker/redis/users.acl`

| User | Can | Notably cannot |
|---|---|---|
| `cs-producer` | `+xadd +set` on `cs:flows`, `cs:dedup:*` | read the stream, create groups, delete anything |
| `cs-consumer` | consume, ack, reclaim, dead-letter | **write to the ingest stream** — a compromised consumer cannot inject fabricated flows into the detection pipeline |
| `cs-observer` | `+xlen +xinfo +xpending` | touch data |
| `cs-admin` | maintenance | — keep off application hosts |

`user default off` — the unauthenticated superuser Redis ships with is disabled.

### Hardening in `redis.conf`

`bind 127.0.0.1`, `protected-mode yes`, and `FLUSHALL`/`FLUSHDB`/`KEYS`/`CONFIG`/`DEBUG`/`SHUTDOWN` renamed away, so an attacker who reaches Redis cannot wipe the backlog, enumerate keys, or rewrite the running configuration. In compose, Redis publishes to `127.0.0.1:6379` only — never `6379:6379`, which would bind every interface.

`appendonly yes` with `appendfsync everysec`: a crash loses at most a second of flows. The stream is a transport, not a system of record — platform state lives in the memory layer.

## Verified end to end

```
1. CAPTURE   : 3 closed pcap(s)
2. CICFLOW   : 16 flows
3. NORMALIZE : 16 flows, 42/42 features
4. PRODUCE   : 16 published, 0 dup suppressed, backlog 0.0%
   REPLAY    : 0 published (expect 0), 16 total dups
5. CONSUME   : 16 flows, pending after ack = 0
6. MODEL     : (16, 42) finite=True -> BENIGN=16
```

## Testing without a server

The stream tests run against **fakeredis**, which implements the full consumer-group API. A durability test that requires infrastructure is a test that gets skipped, and "lose nothing / replay nothing" is exactly the guarantee nobody notices is broken until production.

`fakeredis` is in `requirements-dev.txt`; `redis>=5.0` is a runtime dependency in `requirements.txt`.

## Running Redis

```bash
docker compose up -d redis          # loopback-only, ACL-authenticated
export INGESTION_REDIS_USERNAME=cs-producer
export INGESTION_REDIS_PASSWORD=...   # openssl rand -base64 32
```

There is no Redis **server** on this development host — only the Python client — and the Docker daemon is not running, so the live path is unverified here. The ACL, config, and compose definitions are provided for a host that has one.

## Not yet wired

Nothing calls the producer or consumer yet. Phase 3 connects `CaptureSession.ready_files()` → cicflowmeter → normalizer → producer, and consumer → `SecurityEvent` → `CoordinatorAgent`.

---

# Phase 3 — Bridge

Connects capture to the agent pipeline.

```
ready pcap ─► cicflowmeter ─► normalizer ─► producer ─► Redis Stream
                                                            │
                                    consumer ◄──────────────┘
                                        │
                                 SecurityEvent[] ─► CoordinatorAgent ─► detection…response
```

## The timezone trap

cicflowmeter stamps every flow with `datetime.fromtimestamp(t)` — **local time, naive**. The platform stores UTC everywhere.

Reading that naive value as UTC does not raise. It makes `observed_at` wrong by the host's UTC offset, so `detected_at - observed_at` is negative — and `IncidentHistory.time_to_detect()` discards negative durations. Every flow would report an unmeasurable MTTD, and the LearningAgent report would say *"no incident carries the timestamps needed to measure observation to detection"* — which reads like missing data, not a bug.

Measured on this host (UTC+5:45):

```
cicflowmeter timestamp (local naive): 2026-08-02 01:51:18
naive-as-UTC (the bug)             -> 2026-08-02T01:51:18+00:00
_to_utc (correct)                  -> 2026-08-01T20:06:18+00:00
true utcnow                        -> 2026-08-01T20:06:18+00:00

MTTD proxy  : +0.97s   -> positive and sane
MTTD if bug : -20699s  -> discarded as negative, metric silently unmeasurable
```

Phase 0 persisted stage timestamps specifically so MTTD would be real. A silent offset here would have quietly undone that. `_to_utc` interprets naive timestamps as local and converts; clock skew that would put `observed_at` in the future is clamped to ingest time and logged, rather than propagated into the metrics.

## What Phase 3 delivers

```
ingestion/
├── flows/pcap_processor.py     # closed pcaps → flows → producer
└── bridge/
    ├── event_builder.py        # flow → SecurityEvent (timezone, protocol, features)
    └── pipeline_bridge.py      # consumer → bounded batch → CoordinatorAgent
```

## Batch size is bounded by the coordinator's budget

Each event costs one coordinator dispatch per stage — detection, analysis, decision, response — so N events need **N × 4** dispatches. With the default `coordinator_max_iterations` of 100, a 50-event batch exhausts the budget after 25 and ends the run with the rest pending.

That failure is *safe* — the coordinator reports outstanding work rather than dropping it — but it is silent waste. `PipelineBridge` accepts `coordinator_budget` and caps its own batch at `budget // 4`, so it can never hand the coordinator more than it can drain. It also raises a warning when a completed run leaves `pending_total > 0`, because nothing reads the coordinator's report otherwise.

## Ordering rules that prevent silent loss

| Rule | Why |
|---|---|
| Flows are acked **after** the graph run | A crash mid-run leaves them pending for another consumer to reclaim — this is what makes "lose nothing" true end to end. |
| A failed run acks **nothing** | Retried via reclaim; repeatedly-failing batches reach the dead letter. |
| An unbuildable batch **is** acked | After counting the loss. Redelivering something that cannot be built retries the same failure forever. |
| Capture files are marked processed **after** publishing | A crash mid-file replays it, and `flow_id` dedup absorbs the overlap. Duplicating briefly beats losing permanently. |
| Extraction failures are **not** marked processed | A corrupt read should be retryable; an empty capture should not. |

## Event construction

`severity` and `risk_score` are left at their floor. This is a raw observation — assigning severity here would pre-empt `DetectionAgent` and `AnalysisAgent`, whose job it is.

`NetworkEndpoint.protocol` is a string while flows carry the IANA number, so `6 → "TCP"`, `17 → "UDP"`. An unknown number is preserved as its digits rather than dropped.

One batch shares one `correlation_id`: a single coordinated run carrying N events, which is exactly the shape `CoordinatorAgent` was built for.

## Verified end to end

Real loopback capture through the whole platform:

```
1. CAPTURE  : 3 closed pcap(s)
2. PROCESS  : files=3 flows=55 published=55 in 1.1s
   RERUN    : published=0 (expect 0), skipped=3
3. BRIDGE   : 5 events in 2.6s (0.53s/event)
   batches=1 acked=5 pending=0 detections=5 responses=5 dropped=0
```

Every stage of the six-agent pipeline ran on real captured packets: 5 flows in, 5 detections, 5 responses, nothing pending, nothing dropped. Reprocessing the same files published zero.

## Measured throughput — and what it means

**~0.53 s per event, roughly 2 events/second.** Each event runs four agents with per-stage memory writes and a model inference.

Six seconds of near-idle loopback traffic produced 55 flows. Extrapolated, that is ~550 flows/minute against a ~120 flows/minute capacity — **already over budget on trivial traffic**, before a real interface is tapped.

The layer is built to fail visibly rather than silently here: the stream is bounded, `backlog_ratio()` reports how close it is to evicting, and every drop is counted. But capacity is a real constraint that Phase 5 must address — through sampling with an exposed rate, parallel consumers in the group, or a faster path than one graph run per small batch. It is not a reason to hold Phase 4; it is a reason not to point this at a busy network yet and believe the results.

## Usage

```python
from ingestion.bridge import PipelineBridge
from ingestion.flows.pcap_processor import PcapProcessor

processor = PcapProcessor(normalizer, producer, state_client=redis)
processor.process_ready(session.ready_files())

bridge = PipelineBridge(consumer, runtime, coordinator_budget=100)
bridge.drain(max_batches=10)
```

## Not yet wired

Nothing calls the processor or bridge on a schedule, and no API route exists. Phase 4 adds the authenticated control plane — `POST /ingestion/start`, `/stop`, `GET /status` — that "Go Live" drives, along with the loop that polls `ready_files()` and drains the stream.

---

# Phase 4 — Control Plane

The authenticated lifecycle behind the frontend's "Go Live" button.

## Endpoints

All sit behind `api_router`, which requires `X-API-Key`. Starting a packet capture is the most privileged operation the platform exposes and is never reachable unauthenticated — verified: every route returns **401** without a key.

| Endpoint | Purpose |
|---|---|
| `GET /ingestion/preflight` | Can we go live, and if not, exactly what is missing |
| `GET /ingestion/interfaces` | Capturable interfaces, for the picker |
| `POST /ingestion/start` | Begin capture and feed the pipeline (`?interface=` optional) |
| `POST /ingestion/stop` | Stop worker and capture; idempotent |
| `GET /ingestion/status` | Capture, stream, worker, bridge counters |

`start` returns **409** when already running and **422** when a dependency is missing — a conflict and a precondition failure are different problems for the frontend.

## Preflight: the frontend asks before it offers

`preflight()` checks every dependency and changes nothing, so the UI can disable "Go Live" and explain why:

```json
{
  "ready": false,
  "checks": {"capture_backend": true, "capture_policy": true,
             "stream": false, "normalizer": true, "runtime": true},
  "blockers": ["Redis is unreachable: ... Start it with `docker compose up -d redis`, ..."]
}
```

Blockers are written to be actionable. "Redis is unreachable" is a bug report; "run `docker compose up -d redis`" is a fix.

## Fail closed — and the capture stays off

The property that matters most: when preflight fails, **the capture never starts**. Verified on this host, which has no Redis server:

```
START -> 422
detail: Redis is unreachable: ...
capture running: False | files on disk: 0
```

A capture that began without a reachable stream would write pcaps at 60-second intervals whose flows go nowhere, consume the disk for the full retention window, and report itself healthy the entire time. The check happens before `session.start()`, so nothing is created to clean up.

## The worker

One background thread, because the runtime, agents, and memory provider are module-level singletons shared with the HTTP handlers. Keeping ingestion single-threaded means the only concurrency to tolerate is "worker running while an API request also runs", which the response guard's lock and the memory provider's RLock already cover. Scaling out means a second **process** joining the consumer group, not a second thread.

Each poll: sweep retention if due → process closed captures → drain the stream.

### Shutdown responsiveness

The first live run exposed a real bug. With `max_batches_per_poll: 4` and a batch of 20, `bridge.drain()` could run 80 events back to back — roughly 42 seconds at the measured 0.53 s/event — and `stop()` cannot interrupt it, so shutdown would hang past its join timeout.

The worker now drains **one batch at a time and checks the stop flag between batches**, which also updates `events_processed` per batch instead of only at the end of an iteration. Status stays current during a long drain rather than under-reporting until it finishes.

### Failure handling

An iteration failure is caught, counted, and the loop continues — one bad poll must not kill live ingestion. After `max_consecutive_errors` (default 10) the worker stops and reports unhealthy, so an unreachable dependency spins down instead of retrying at full speed forever. `last_error` is retained in status.

## Secrets

`status()` and `preflight()` never include a credential. The Redis URL is stripped from the health snapshot because some deployments embed credentials in it. Verified with a password set in the environment: it appears nowhere in either payload, and a test pins it.

## Verified live

Full Go Live on the loopback interface, with a stream client injected because this host has no Redis server:

```
preflight ready: True | checks: all true
GO LIVE -> running: True
  t= 6s polls=1 files=1 published=15 events=15 detections=15 responses=15 errors=0
  t=12s polls=2 files=6 published=72 events=15 detections=15 responses=15 errors=0
  t=18s polls=2 files=6 published=72 events=15 detections=35 responses=35 errors=0
stream: {"reachable": true, "stream_length": 72, "backlog_ratio": 0.0007,
         "pending": 20, "dead_letter": 0}
STOPPED -> running: False | capture: False
```

Capture, extraction, publication, consumption, and all six agents ran on real packets under API control, then stopped cleanly.

## The backlog is visible, which is the point

Read that run again: **72 flows published, 35 processed, 20 pending.** The pipeline fell behind within eighteen seconds of near-idle loopback traffic.

That is the capacity constraint from Phase 3 reproduced live — and the layer reports it rather than hiding it. `stream_length`, `backlog_ratio`, and `pending` are all in `/ingestion/status`, so the dashboard can show the platform falling behind instead of quietly dropping flows. Phase 5 has to close the gap; until then, do not point this at a busy network and trust the numbers.

## Usage

```bash
curl -H "X-API-Key: ..." localhost:8000/ingestion/preflight
curl -H "X-API-Key: ..." localhost:8000/ingestion/interfaces
curl -X POST -H "X-API-Key: ..." "localhost:8000/ingestion/start?interface=Wi-Fi"
curl -H "X-API-Key: ..." localhost:8000/ingestion/status
curl -X POST -H "X-API-Key: ..." localhost:8000/ingestion/stop
```

The service is constructed at startup but **never auto-started**: beginning a packet capture must be an explicit operator decision, not a side effect of booting the server.

## Remaining for Phase 5

Throughput. Sampling with an exposed rate, parallel consumer processes, or a faster path than one graph run per small batch — plus the live `cicflowmeter -i` source that cuts the 60-second rotation latency.

---

# Phase 4b — Remote Ingest

Everything above assumes the network worth watching is the one the dashboard
runs on. Frequently it is not: the platform sits on a laptop or a management
box, and the traffic is on a gateway, a DMZ host, or a machine in another
building that will never run a React app.

Remote ingest joins the pipeline at "closed pcaps" over HTTP instead of from
local disk:

```
capture mode   this host's NIC ──► dumpcap ──► closed pcaps ─┐
                                                             ├─► flows ─► stream ─► agents
remote mode    a sensor elsewhere ──HTTP──► /ingestion/pcap ─┘
```

Same `PcapProcessor`, same normalizer, same feature contract, same stream. A
submitted capture produces alerts indistinguishable from a locally captured
one. That is the point — and it is also the entire risk, which is why most of
this section is about what the endpoint refuses.

## Two modes, one worker

`POST /ingestion/start?mode=remote` starts the worker — stream drain, retention
sweep, counters — and **does not start dumpcap**. Nothing on this host is
captured, and no capture privileges are needed.

The mode is not a cosmetic flag; it changes what preflight demands:

| Check | capture | remote |
|---|---|---|
| `capture_backend` (dumpcap present) | required | not checked |
| `capture_policy` (interface, snaplen, ring) | required | not checked |
| `upload_policy` (writable dir, size ceiling) | — | required |
| `stream`, `normalizer`, `runtime` | required | required |

Preflight takes `?mode=` for exactly this reason. Asking the capture-mode
question on a host with no dumpcap would grey out "Go Live" for an operator
whose sensors are all elsewhere — reporting *cannot ingest anything* about a
platform that can ingest everything it is sent.

`mode` is parsed strictly. An unrecognized value is a **422**, never a fallback
to `capture`: defaulting on a typo would start a real packet capture for
someone who asked for the mode that taps nothing.

An `?interface=` alongside `mode=remote` is refused rather than ignored —
silently dropping it would leave the operator believing it was applied.

## The endpoint

```
POST /ingestion/pcap        multipart/form-data, field name `file`
```

Authenticated like every other ingestion route. **Synchronous by design**: flow
extraction runs before the response, so the sender is told what its own
submission produced rather than getting an ack and no answer.

```json
{
  "accepted": true, "duplicate": false,
  "filename": "sensor.pcap", "stored_as": "rx_16b45bdf5ab0bb30….pcap",
  "source": "127.0.0.1",
  "flows_extracted": 1, "flows_published": 1, "flows_rejected": 0,
  "message": "1 flow(s) published to the pipeline."
}
```

Extraction runs in the threadpool — it is CPU-bound, and on the event loop it
would stall every other request on the server.

## Status codes an unattended sender can act on

A capture agent running on cron cannot parse prose. Each refusal maps to one
decision:

| Code | Meaning | What the sender should do |
|---|---|---|
| 409 | Not running in remote mode | Retry later; ask the operator to go live |
| 413 | Over the size ceiling | Rotate captures smaller |
| 415 | Not a pcap/pcapng | Fix the format — `editcap -F pcap` |
| 422 | Unreadable, or off-contract flows | Do **not** retry unchanged |

## What the endpoint refuses, and why

This ingress writes caller-supplied bytes to disk before anything parses them,
and the only credential in front of it is a key the dashboard also carries. So
every limit is enforced **while the body streams**, not after it is in memory.

**Size, twice.** `Content-Length` is checked first as a courtesy — an honest
sender learns immediately instead of pushing 2 GB uphill. But a declared length
is a number the sender chose, so the real ceiling is counted chunk by chunk as
bytes arrive. `upload.max_file_mb` (default 256) governs both.

**Format, on the first bytes.** The filename extension is a courtesy check; the
gate that matters is the pcap/pcapng magic number on the first chunk. Without
it, arbitrary caller-supplied bytes would reach the flow extractor.

**The filename is discarded entirely.** A submission is stored under the SHA-256
of its own content, never anything the caller supplied — the only way to be
certain a remote sender cannot steer where the file lands.

**Replay.** Content-addressing does double duty: `PcapProcessor`'s
processed-file set keys on the name and persists in Redis, so byte-identical
resubmissions are recognized and skipped across restarts. This matters more
here than anywhere else in the platform — the pipeline deliberately treats
repeated identical flows as signal, so a sensor retrying a timed-out upload
could otherwise fabricate a volumetric attack out of one honest capture.

**Retention.** A submission is deleted the moment it is processed, on every
path including failure. Submitted traffic is exactly as sensitive as captured
traffic and has no ring buffer bounding it. `upload.retention_seconds` (default
1 h) is only a backstop for what a crash leaves behind.

### The cleanup bug this found

Deleting the file lives in a `finally`, and on Windows a failed cicflowmeter
run leaves the handle open. The `PermissionError` from `unlink` replaced the
real exception — turning a precise *"this file is unreadable"* into an opaque
server error, on the one path where the sender most needs to know what it did
wrong. Cleanup is now best-effort and never masks the outcome; the sweeper
collects the leftover. A test pins it.

## Trust

An operator sees this in preflight warnings and on the dashboard:

> Remote ingest is open: any caller with the API key can submit traffic that
> the pipeline will treat as observed reality. Flows carry the sender's
> addresses, not this host's — attribution in alerts is only as trustworthy as
> the sender.

Rejections are counted separately from acceptances (`received`, `accepted`,
`duplicates`, `rejected`, `failed`, `last_error`, `last_source`) so a
misconfigured sensor whose files all bounce does not look like a quiet network.

## Configuration

```yaml
upload:
  max_file_mb: 256                              # enforced mid-stream
  work_dir: uploads                             # separate from capture.output_dir
  retention_seconds: 3600                       # backstop, not a policy
  allowed_suffixes: [".pcap", ".pcapng", ".cap"]
```

`work_dir` is deliberately not the capture ring: a remote sender must never be
able to touch local capture files or the retention window over them.

## The dashboard

The interface picker gained a second group. "Tap this host" lists real
interfaces; "Tap another host" offers **Remote sensors (submitted pcaps)**,
which is a mode rather than an interface. Choosing it re-runs preflight in
remote mode, so a host without dumpcap can still go live.

While in remote mode the Capture Detail panel is replaced by **Remote Ingest**,
which carries the copy-ready `curl` for the other server, the endpoint and
limits, the trust warning, and the submission counters — plus a file picker
that posts to the same endpoint, so the chain can be proven from the dashboard
before configuring a machine that may not have a browser.

## Verified live

Against a running server, with a scapy-built pcap standing in for a remote
sensor:

```
preflight capture : ready=True  checks={capture_backend, capture_policy, stream, normalizer, runtime}
preflight remote  : ready=True  checks={upload_policy, stream, normalizer, runtime}

submit before live       -> 409  "Ingestion is not running, so submitted flows would reach no agent…"
start ?mode=remote       -> 200  running=True mode=remote capture running=False
submit sensor.pcap       -> 200  accepted=true extracted=1 published=1 stored_as=rx_16b45bdf…pcap
submit identical bytes   -> 200  duplicate=true published=0
submit a shell script    -> 415  "'evil.pcap' is not a pcap or pcapng file…"

uploads: received=3 accepted=1 duplicates=1 rejected=1 failed=0
uploads/ after stop: []          # nothing retained
```

And the worker drains the stream in remote mode exactly as it does in capture
mode — six agents running on flows that arrived over HTTP:

```
  polls=1  events=20   detections=20   responses=20   acked=20   errors=0
  polls=1  events=60   detections=60   responses=60   acked=60   errors=0
  polls=2  events=120  detections=120  responses=120  acked=120  errors=0
```

## Usage

On the sensor host:

```bash
# rotate captures locally, ship each closed file
dumpcap -i eth0 -s 96 -b duration:60 -b files:2 -w /tmp/sensor.pcap

curl -X POST http://<platform-host>:8000/ingestion/pcap \
     -H "X-API-Key: $CYBER_SURAKSHYA_API_KEY" \
     -F "file=@/tmp/sensor_00001.pcap"
```

On the platform host:

```bash
curl -H "X-API-Key: ..." "localhost:8000/ingestion/preflight?mode=remote"
curl -X POST -H "X-API-Key: ..." "localhost:8000/ingestion/start?mode=remote"
curl -H "X-API-Key: ..." localhost:8000/ingestion/status     # .uploads, .remote
```

## Known limitations

- **One at a time.** Submissions are serialized behind a lock: extraction is
  CPU-heavy and the processor's counters are plain integers. Concurrent senders
  queue rather than corrupt each other.
- **The Phase 3 capacity ceiling still applies** — ~2 events/second through the
  agent pipeline. Remote ingest makes it *easier* to exceed, because a sender
  can submit an hour of traffic in one request. The backlog is visible in
  `/ingestion/status`, and it is still the constraint Phase 5 has to close.
- **The API key is the only authorization.** There is no per-sensor identity,
  no rate limit, and no allowlist of sources. `source` is recorded for
  attribution but nothing is authorized by it.
