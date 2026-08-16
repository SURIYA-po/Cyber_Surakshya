# Implementation Plan: Real-Time Ingestion Layer

> Answers the two questions driving this phase:
> **How does the system get real data securely?** and **How does it get it continuously?**
>
> Depends on: the complete six-agent pipeline (all ✅), `cicflowmeter` (vendored in-workspace), Docker (v29.4.3 available).

---

## 0. Verdict on the proposed design

The proposal — Wireshark in Docker → rotating pcap files → cicflowmeter → Redis Streams → CoordinatorAgent — is **structurally correct**. Capture is isolated, flow extraction is reused rather than reinvented, the stream decouples capture rate from pipeline rate, and the coordinator already drains a batch. Four changes follow, and one blocking prerequisite that must be fixed before any of it is built.

---

## 1. BLOCKING: the feature contract is broken today

Measured against the workspace, not assumed:

```
model features (artifacts/feature_columns.json) : 42
mapped from cicflowmeter output (out.csv)       : 0
MISSING                                         : 42
```

**Zero of 42 features currently map.** `inference.CICFLOW_ALIASES` handles the *Java* CICFlowMeter naming (space-prefixed Title Case, `" Flow Duration"`). The vendored tool is the *Python* cicflowmeter, which emits snake_case (`flow_duration`, `fwd_pkt_len_max`, `tot_fwd_pkts`). The two naming schemes never meet.

If the ingestion layer is built before this is fixed, the pipeline runs end to end, the dashboard fills with alerts, and every prediction is meaningless.

### 1.1 The dangerous half: units, not names

Renaming alone is not enough, and this is the failure that would have survived review:

| | CICIDS2017 (model was trained on) | Python cicflowmeter (measured in `out.csv`) |
|---|---|---|
| `Flow Duration` | **microseconds** — `app.py` attack profiles use `30000000` (30 s), `3600000000` (1 h) | **seconds** — median `0.00097`, max `10.48` |

A rename-only mapping feeds the model values **10⁶ times too small**. Every real flow would look like a near-instantaneous flow. The model would not error — it would return confident, plausible, systematically wrong labels, and `LearningAgent` would faithfully report high accuracy on them because analysts have no reason to suspect the input.

**13 of the 42 features are time-domain and need ×1 000 000:**
`Flow Duration`, `Flow IAT Mean/Std/Max`, `Fwd IAT Total/Mean/Std/Max`, `Bwd IAT Total/Max`, `Idle Mean/Max/Min`.

**4 are rates and must NOT be scaled** — per-second in both schemes:
`Flow Bytes/s`, `Flow Packets/s`, `Fwd Packets/s`, `Bwd Packets/s`.

Scaling the rate columns by mistake is the same bug with the sign flipped, so the normalizer must treat the two groups explicitly rather than pattern-matching on names.

### 1.2 A corrupted artifact

`artifacts/feature_columns.json` contains `"pyDestination Port"`. The typo comes from the **training dataset header** — the first column of `data/cicids2017_cleaned.csv` is literally named `pyDestination Port`, and `preprocess.select_features` carries column names through verbatim. The column holds genuine destination ports (scaler stats at index 25: `mean=4306.3`, `scale=12838.7`). The scaler is **positional** (`n_features_in_=42`, `feature_names_in_=None`), so training and inference are unaffected today; only name-based column selection breaks. Live ingestion is name-based, so it must be corrected to `"Destination Port"`.

Because the scaler is positional, the fix is a pure rename at the same index — **no retraining, no reordering**. Verified by asserting predictions on a fixed input are byte-identical before and after.

### 1.3 The complete mapping (all 42 verified against `out.csv`)

```
Destination Port ← dst_port                Flow Duration ← flow_duration            ×1e6
Total Fwd Packets ← tot_fwd_pkts           Flow IAT Mean ← flow_iat_mean            ×1e6
Total Length of Fwd Packets ← totlen_fwd_pkts   Flow IAT Std ← flow_iat_std         ×1e6
Fwd Packet Length Max ← fwd_pkt_len_max    Flow IAT Max ← flow_iat_max              ×1e6
Fwd Packet Length Mean ← fwd_pkt_len_mean  Fwd IAT Total ← fwd_iat_tot              ×1e6
Fwd Packet Length Std ← fwd_pkt_len_std    Fwd IAT Mean ← fwd_iat_mean              ×1e6
Bwd Packet Length Max ← bwd_pkt_len_max    Fwd IAT Std ← fwd_iat_std                ×1e6
Bwd Packet Length Min ← bwd_pkt_len_min    Fwd IAT Max ← fwd_iat_max                ×1e6
Bwd Packet Length Mean ← bwd_pkt_len_mean  Bwd IAT Total ← bwd_iat_tot              ×1e6
Bwd Packet Length Std ← bwd_pkt_len_std    Bwd IAT Max ← bwd_iat_max                ×1e6
Min Packet Length ← pkt_len_min            Idle Mean ← idle_mean                    ×1e6
Max Packet Length ← pkt_len_max            Idle Max ← idle_max                      ×1e6
Packet Length Mean ← pkt_len_mean          Idle Min ← idle_min                      ×1e6
Packet Length Std ← pkt_len_std            ── rates: NO conversion ──
Packet Length Variance ← pkt_len_var       Flow Bytes/s ← flow_byts_s
Average Packet Size ← pkt_size_avg         Flow Packets/s ← flow_pkts_s
Fwd Header Length ← fwd_header_len         Fwd Packets/s ← fwd_pkts_s
Bwd Header Length ← bwd_header_len         Bwd Packets/s ← bwd_pkts_s
Subflow Fwd Bytes ← subflow_fwd_byts       FIN Flag Count ← fin_flag_cnt
Init_Win_bytes_forward ← init_fwd_win_byts PSH Flag Count ← psh_flag_cnt
Init_Win_bytes_backward ← init_bwd_win_byts ACK Flag Count ← ack_flag_cnt
min_seg_size_forward ← fwd_seg_size_min
```

---

## 2. Change 1 — `dumpcap`, not Wireshark

Wireshark is a GUI application; in a container you would end up invoking its capture engine anyway. Use that engine directly:

- **`dumpcap`** is the minimal-privilege capture binary Wireshark and tshark both shell out to. It is the smallest attack surface of the three, and the only one designed to run unattended.
- It performs **native ring-buffer rotation**: `-b duration:60 -b files:120` writes a new file every 60 s and keeps the last 120. No cron job, no timer, no custom rotation logic to get wrong.
- It supports **snaplen** (`-s 96`), which is the single most valuable security control in this whole design — see §5.

---

## 3. Change 2 — two sources, one stream

The proposal treats the pcap file as the transport. It is better used as **evidence**, with a second path carrying the latency-sensitive traffic. Both write the same normalized flow to the same Redis stream, so nothing downstream knows or cares which produced it.

```
┌── capture container (dumpcap, CAP_NET_RAW only) ──────────────┐
│  -s 96  -b duration:60  -b files:120  -w /captures/cs.pcap    │
└───────┬──────────────────────────────────────┬────────────────┘
        │ rotated pcap files (evidence)        │ live interface
        ▼                                      ▼
  PcapProcessor                          LiveFlowSource
  (offline cicflowmeter)                 (cicflowmeter -i)
        └──────────────┬───────────────────────┘
                       ▼
                FlowNormalizer          ← §1: names + units
                       ▼
              Redis Stream  cs:flows    ← MAXLEN, consumer group
                       ▼
                StreamConsumer          ← batch, dedup, ack
                       ▼
              SecurityEvent[] → CoordinatorAgent → existing pipeline
```

**Why both.** The 60-second rotation gives a floor of 60 s and a mean near 90 s before a flow is even seen — measurable directly as the `mttd_seconds` metric built in the last phase. That is acceptable for forensics and unacceptable for containment. The live path brings MTTD to seconds; the pcap path keeps the raw evidence a SOC actually needs for post-incident work and replay.

They share the normalizer, the producer, and everything downstream — the incremental cost of the second source is one small module.

**If only one is built first**, build the pcap path: it is simpler, it is what was proposed, and it produces the artifacts. Architect `FlowNormalizer` and the producer so `LiveFlowSource` drops in without touching them.

### 3.1 The file-completion race

Never read a pcap `dumpcap` is still writing — a truncated final packet silently produces a corrupt final flow. dumpcap's ring buffer guarantees file *N* is closed once file *N+1* exists. So: **process only files that are not the newest**, and additionally require the size to be unchanged across two poll intervals. Track processed files by name in Redis so a restart does not reprocess or skip.

---

## 4. Change 3 — Redis Streams is right, but not for the stated reason

Redis Streams is the correct choice. It provides durability across a consumer restart, consumer groups with pending-entry recovery, replay from an offset, and natural backpressure through a bounded stream.

It is **not** a security control. Redis binds to all interfaces with no authentication by default. The security in this design comes from §5, not from Redis. Specifically required:

- `requirepass` plus a dedicated ACL user per role: the producer gets `+xadd` on `cs:flows` **only**; the consumer gets `+xreadgroup +xack`. Neither gets `FLUSHALL`, `CONFIG`, or `KEYS`.
- TLS if Redis is not on the same Docker network; bound to `127.0.0.1` or an internal network otherwise, never published to the host.
- `XADD ... MAXLEN ~ 100000` so a traffic burst cannot exhaust memory.

---

## 5. Answering "securely" properly

The capture layer is the highest-privilege component in the platform. It sees all traffic on the segment, and it is the one place where a compromise yields plaintext credentials.

| Control | Why it matters |
|---|---|
| **`-s 96` snaplen** | Captures headers, discards payloads. Every flow feature is computable from headers, so payloads are pure liability — passwords, session tokens, PII, all written to disk for nothing. **This is the highest-value control here and costs one flag.** |
| **`--cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN`** | Never `--privileged`. dumpcap drops privileges after opening the socket. |
| **Non-root user, read-only rootfs** | The container writes only to the pcap volume. |
| **No egress from the capture container** | It captures and writes. It has no reason to reach the network, and denying it removes the exfiltration path. |
| **`--net=host` is the unavoidable tradeoff** | Required to observe host traffic. Compensate with everything above rather than pretending it is free. |
| **BPF filter at capture time** | Exclude sensitive segments (management VLAN, backup networks) *before* anything reaches disk. Filtering later is not the same guarantee. |
| **pcap retention + volume permissions** | `-b files:120` caps disk at ~2 h. The volume is mounted **read-only** into the processor. Capture metadata is sensitive data. |
| **Authenticated control plane** | "Go Live" starts a packet capture — a privileged operation. It goes behind the existing `X-API-Key` dependency, never an unauthenticated route. |
| **Redis ACL + TLS + bounded stream** | §4. |
| **Flow-level dedup (`flow_id`)** | Replaying a pcap must not double-count incidents; the platform already treats repeated flows as signal, so duplicates would fabricate a DDoS. |

---

## 6. Change 4 — backpressure must be explicit

A busy interface produces flows far faster than a four-agent LangGraph pipeline with per-stage memory writes can consume them. This will saturate, and the only question is whether it does so visibly.

- **Bounded stream** (`MAXLEN ~`) — Redis evicts oldest under pressure.
- **Bounded batch per run** — consume ≤ `N` flows (default 50) into one state and run the coordinator once. `coordinator_max_iterations` and the derived recursion limit already handle this; the batch cap simply needs to align with it.
- **A drop counter, never a silent drop.** Every discarded flow increments a metric surfaced in `/ingestion/status`. The lesson from `LearningAgent` applies directly: a system that hides what it did not process reports success it did not earn.
- **Prioritised sampling under load** — when the backlog exceeds a threshold, sample benign-looking flows and keep everything else. Document it as sampling, and expose the rate.

---

## 7. Folder Structure

```
ingestion/                             # NEW
├── __init__.py
├── config.py                          # capture + stream policy (YAML-backed, fail-closed)
├── capture/
│   ├── docker_runner.py               # dumpcap container lifecycle
│   └── session.py                     # CaptureSession: start / stop / status
├── flows/
│   ├── normalizer.py                  # ⚠ §1 — names + units. The critical module.
│   ├── pcap_processor.py              # closed-file watcher → flows
│   └── live_source.py                 # cicflowmeter -i → flows
├── stream/
│   ├── producer.py                    # XADD, MAXLEN, flow_id
│   └── consumer.py                    # XREADGROUP, ack, pending recovery, dedup
└── bridge/
    └── event_builder.py               # flow dict → SecurityEvent

config/ingestion_policy.yaml           # NEW — interface, snaplen, BPF, rotation, retention, batch caps
docker/capture/Dockerfile              # NEW — dumpcap, non-root
docker-compose.yml                     # NEW — redis + capture + api

artifacts/feature_columns.json         # EDIT — "pyDestination Port" → "Destination Port"

tests/ingestion/test_flow_normalizer.py   # NEW — the golden test
tests/ingestion/test_stream.py            # NEW
tests/ingestion/test_pcap_processor.py    # NEW
docs/realtime_ingestion.md                # NEW
```

`ingestion/` is a peer of `adapters/`, not part of it: `adapters/detection/` bridges a detector into platform schemas, while this produces the `SecurityEvent`s that reach a detector. Different direction, different boundary.

---

## 8. Build Order

**Phase 0 — the feature contract (blocking).**
Fix `feature_columns.json`. Build `FlowNormalizer` with the §1.3 table and explicit unit conversion. Golden test: `malware_c2.pcap` → cicflowmeter → normalizer → all 42 features present, correct dtype, `Flow Duration` in the 10⁴–10⁹ range, rate columns unscaled. Assert predictions on a fixed vector are unchanged by the artifact rename. **Nothing else starts until this passes.**

**Phase 1 — capture.** Dockerfile, `docker_runner`, `CaptureSession`, rotation and retention, snaplen and BPF from config. Verify pcaps appear, rotate, and expire; verify the container runs non-root without `--privileged`.

**Phase 2 — stream.** Redis service with ACL users, producer with `MAXLEN` and `flow_id`, consumer group with pending recovery. Verify a consumer restart loses nothing and replays nothing.

**Phase 3 — pipeline bridge.** `pcap_processor` (closed files only) → normalizer → producer; `consumer` → `event_builder` → batched `CoordinatorAgent` run. End-to-end: real capture produces real alerts with correct labels.

**Phase 4 — control plane.** `POST /ingestion/start`, `POST /ingestion/stop`, `GET /ingestion/status`, `GET /ingestion/stats` behind `X-API-Key`. This is what "Go Live" calls.

**Phase 5 — live source + hardening.** `live_source.py` for low-latency MTTD; drop counters, sampling policy, ingestion health in `/learning/metrics`.

Per AI_DEVELOPMENT_RULES §7, work stops after Phase 5, before the frontend build.

---

## 9. Two smaller findings

- **`cicflowmeter/src/cicflowmeter/writer.py::HttpWriter.write`** references `self.logger`, which `HttpWriter` does not define. Any POST failure raises `AttributeError` from inside the exception handler, masking the original error. One line to fix, and it sits on the `-u/--url` path this design may use.
- **`EXPIRED_UPDATE = 240`** means an idle flow is not emitted for up to 4 minutes. For long-lived C2 beaconing — exactly what `malware_c2.pcap` contains — this dominates MTTD regardless of transport choice. Consider lowering it for the live path, and measure the effect on flow-feature fidelity before adopting it.

---

## 10. Open Questions

1. **Capture interface and segment** — which host/VLAN, and is there a SPAN/mirror port, or is this host-local traffic only? This decides whether the platform sees a network or one machine.
2. **Snaplen 96 acceptable?** Recommended yes. It forecloses future payload-based (DPI) detection, which is a real tradeoff worth making consciously rather than by default.
3. **Retention for pcap evidence** — `-b files:120` gives ~2 h. Compliance may require longer, which changes the volume sizing.
