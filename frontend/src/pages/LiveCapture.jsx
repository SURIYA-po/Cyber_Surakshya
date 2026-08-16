import { useCallback, useEffect, useRef, useState } from "react";
import {
  Radio, Play, Square, RefreshCw, AlertTriangle, CheckCircle2,
  HardDrive, Activity, Layers, Gauge, ShieldAlert, Network,
  Cloud, Upload, Copy, Check, Inbox,
} from "lucide-react";
import Panel from "../components/common/Panel";
import {
  REMOTE_OPTION, getApiBaseUrl,
  getPreflight, getInterfaces, getIngestionStatus,
  startIngestion, stopIngestion, uploadPcap,
} from "../api/ingestionApi";

const POLL_MS = 3000;

function Stat({ label, value, sub, icon: Icon, tone = "var(--accent)" }) {
  return (
    <div className="card" style={{ padding: "1rem 1.125rem" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <p style={{ fontSize: 11, color: "var(--text-secondary)" }}>{label}</p>
        <Icon size={13} color={tone} />
      </div>
      <p style={{ fontSize: 22, fontWeight: 700, color: "var(--text-primary)", lineHeight: 1.1 }}>{value}</p>
      {sub && <p style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>{sub}</p>}
    </div>
  );
}

/**
 * Stream backlog. Deliberately prominent: Redis trims silently when the
 * stream is full, so this bar is the only warning that flows are about to be
 * lost to backpressure.
 */
function BacklogBar({ stream }) {
  const ratio = stream?.backlog_ratio ?? 0;
  const pct = Math.min(100, ratio * 100);
  const tone = pct > 80 ? "var(--red)" : pct > 40 ? "var(--yellow)" : "var(--green)";

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
        <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
          Stream backlog — {stream?.stream_length ?? 0} / {stream?.max_length ?? 0}
        </span>
        <span style={{ fontSize: 11, fontWeight: 600, color: tone }}>
          {pct < 0.1 && pct > 0 ? "<0.1" : pct.toFixed(1)}%
        </span>
      </div>
      <div style={{ height: 6, borderRadius: 4, background: "var(--bg-input)", overflow: "hidden" }}>
        <div style={{ width: `${Math.max(pct, ratio > 0 ? 1.5 : 0)}%`, height: "100%", background: tone, transition: "width .4s" }} />
      </div>
      <div style={{ display: "flex", gap: "1.25rem", marginTop: 10 }}>
        <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
          In flight <strong style={{ color: "var(--text-primary)" }}>{stream?.pending ?? 0}</strong>
        </span>
        <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
          Dead letter{" "}
          <strong style={{ color: (stream?.dead_letter ?? 0) > 0 ? "var(--red)" : "var(--text-primary)" }}>
            {stream?.dead_letter ?? 0}
          </strong>
        </span>
      </div>
      {(stream?.pending ?? 0) > 0 && (
        <p style={{ fontSize: 11, color: "var(--yellow)", marginTop: 10, lineHeight: 1.5 }}>
          The pipeline is behind the capture. Flows are queued, not lost — but sustained
          backlog means the platform is not keeping up with this interface.
        </p>
      )}
    </div>
  );
}

function Blocker({ text }) {
  return (
    <div style={{
      display: "flex", gap: 10, alignItems: "flex-start",
      background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.22)",
      borderRadius: "var(--radius)", padding: "0.7rem 0.875rem", marginBottom: 8,
    }}>
      <AlertTriangle size={14} color="var(--red)" style={{ flexShrink: 0, marginTop: 2 }} />
      <p style={{ fontSize: 12, color: "#FCA5A5", lineHeight: 1.55 }}>{text}</p>
    </div>
  );
}

function CheckRow({ name, ok }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "0.4rem 0" }}>
      {ok
        ? <CheckCircle2 size={13} color="var(--green)" />
        : <AlertTriangle size={13} color="var(--red)" />}
      <span style={{ fontSize: 12, color: ok ? "var(--text-primary)" : "#FCA5A5", textTransform: "capitalize" }}>
        {name.replace(/_/g, " ")}
      </span>
    </div>
  );
}

/** A shell command with a copy button. The command is the deliverable here —
 *  an operator configuring a sensor on another host cannot retype it. */
function Command({ text }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard access is denied over plain HTTP on some hosts. The text is
      // selectable either way, so this fails quietly rather than alarming.
    }
  }

  return (
    <div style={{ position: "relative" }}>
      <pre
        className="mono"
        style={{
          fontSize: 11, lineHeight: 1.7, color: "var(--text-primary)",
          background: "var(--bg-input)", border: "1px solid var(--border)",
          borderRadius: "var(--radius)", padding: "0.75rem 2.5rem 0.75rem 0.875rem",
          overflowX: "auto", whiteSpace: "pre", margin: 0,
        }}
      >
        {text}
      </pre>
      <button
        className="btn-ghost"
        onClick={copy}
        title="Copy to clipboard"
        style={{ position: "absolute", top: 6, right: 6, padding: "0.3rem 0.4rem" }}
      >
        {copied ? <Check size={12} color="var(--green)" /> : <Copy size={12} />}
      </button>
    </div>
  );
}

/**
 * Remote ingest — what a sensor on another host needs, and proof it works.
 *
 * Shown when the platform is in remote mode. The upload control here is the
 * same endpoint a remote sensor posts to, so an operator can confirm the
 * pipeline end to end before going to configure a machine they may not have
 * a browser on.
 */
function RemoteIngestPanel({ remote, uploads, accepting, onIngested }) {
  const [file, setFile]         = useState(null);
  const [busy, setBusy]         = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult]     = useState(null);
  const [error, setError]       = useState(null);
  const inputRef = useRef(null);

  const endpoint = `${getApiBaseUrl()}${remote?.endpoint || "/ingestion/pcap"}`;
  const suffixes = (remote?.allowed_suffixes || [".pcap", ".pcapng"]).join(",");

  const curl = [
    `curl -X POST ${endpoint} \\`,
    `     -H "X-API-Key: $CYBER_SURAKSHYA_API_KEY" \\`,
    `     -F "file=@capture.pcap"`,
  ].join("\n");

  async function submit() {
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    setProgress(0);
    try {
      const data = await uploadPcap(file, setProgress);
      setResult(data);
      setFile(null);
      if (inputRef.current) inputRef.current.value = "";
      onIngested?.();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Upload failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Remote Ingest" accent="#8B5CF6">
      <div style={{
        display: "flex", alignItems: "center", gap: 8, marginBottom: 12,
      }}>
        <Cloud size={14} color={accepting ? "var(--green)" : "var(--text-muted)"} />
        <span style={{ fontSize: 12, color: accepting ? "var(--green)" : "var(--text-secondary)" }}>
          {accepting
            ? "Accepting submissions from remote sensors"
            : "Not accepting — go live in remote mode first"}
        </span>
      </div>

      <p style={{ fontSize: 11, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 12 }}>
        Sensors elsewhere POST closed pcaps to this endpoint. They join the same
        pipeline as a local capture — same flow extraction, same agents, same
        alerts. Run this on the other server:
      </p>

      <Command text={curl} />

      <div style={{ marginTop: 12, marginBottom: 16 }}>
        <Row label="Endpoint" value={endpoint} mono />
        <Row label="Auth header" value="X-API-Key" mono />
        <Row label="Max file size" value={`${remote?.max_file_mb ?? 0} MB`} />
        <Row label="Accepted" value={remote?.allowed_suffixes?.join("  ") || "—"} mono />
      </div>

      <p style={{ fontSize: 11, color: "var(--yellow)", lineHeight: 1.6, marginBottom: 16 }}>
        A submission is traffic this platform did not witness. Flows carry the
        sender's addresses, so alerts are only as trustworthy as the sensor —
        and anything holding the API key can submit.
      </p>

      {/* Same endpoint, from here — so the chain can be proven before touching
          a remote host. */}
      <div style={{ borderTop: "1px solid var(--border)", paddingTop: "1rem" }}>
        <p style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 10 }}>
          Or send one from this browser to test the chain:
        </p>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input
            ref={inputRef}
            type="file"
            accept={suffixes}
            disabled={!accepting || busy}
            onChange={(e) => { setFile(e.target.files?.[0] || null); setResult(null); setError(null); }}
            className="input-base"
            style={{ fontSize: 11, padding: "0.4rem", flex: 1, minWidth: 190 }}
          />
          <button
            className="btn-primary"
            onClick={submit}
            disabled={!file || !accepting || busy}
          >
            <Upload size={12} /> {busy ? `Sending ${progress}%` : "Submit pcap"}
          </button>
        </div>

        {error && (
          <p style={{ fontSize: 11, color: "#FCA5A5", marginTop: 10, lineHeight: 1.55 }}>
            {error}
          </p>
        )}

        {result && (
          <p style={{
            fontSize: 11, marginTop: 10, lineHeight: 1.55,
            color: result.duplicate ? "var(--yellow)" : "var(--green)",
          }}>
            {result.duplicate
              ? `${result.filename}: identical bytes were already ingested — skipped so a retry cannot duplicate traffic.`
              : `${result.filename}: ${result.flows_published} flow(s) published${
                  result.flows_rejected ? `, ${result.flows_rejected} rejected` : ""
                }.`}
          </p>
        )}
      </div>

      <div style={{ marginTop: "1rem", paddingTop: "1rem", borderTop: "1px solid var(--border)" }}>
        <Row label="Submissions received" value={uploads?.received ?? 0} />
        <Row label="Accepted" value={uploads?.accepted ?? 0} />
        <Row label="Duplicates skipped" value={uploads?.duplicates ?? 0} />
        <Row label="Rejected" value={uploads?.rejected ?? 0}
             tone={(uploads?.rejected ?? 0) > 0 ? "var(--yellow)" : undefined} />
        <Row label="Failed" value={uploads?.failed ?? 0}
             tone={(uploads?.failed ?? 0) > 0 ? "var(--red)" : undefined} />
        <Row label="Data received" value={`${uploads?.mb_received ?? 0} MB`} />
        <Row label="Last sender" value={uploads?.last_source} mono />
        <Row label="Last file" value={uploads?.last_filename} mono />
        {uploads?.last_error && (
          <p style={{ fontSize: 11, color: "var(--yellow)", marginTop: 8, lineHeight: 1.5 }}>
            Last rejection: {uploads.last_error}
          </p>
        )}
      </div>
    </Panel>
  );
}

export default function LiveCapture() {
  const [preflight, setPreflight] = useState(null);
  const [status, setStatus] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [selected, setSelected] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const running = status?.running ?? false;

  // While stopped the picker decides the mode; while running the backend does,
  // so the page cannot claim a mode the platform is not actually in.
  const wantsRemote = selected === REMOTE_OPTION;
  const remoteMode  = running ? status?.mode === "remote" : wantsRemote;
  const mode        = remoteMode ? "remote" : "capture";

  const refresh = useCallback(async () => {
    try {
      // Preflight is asked about the mode the operator is about to start:
      // remote mode needs no dumpcap, so checking for one would grey out
      // "Go Live" on a host that can ingest perfectly well.
      const [pf, st] = await Promise.all([
        getPreflight(wantsRemote ? "remote" : undefined),
        getIngestionStatus(),
      ]);
      setPreflight(pf);
      setStatus(st);
      if (!selected && st?.mode === "remote") setSelected(REMOTE_OPTION);
      else if (!selected && st?.capture?.interface) setSelected(st.capture.interface);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  }, [selected, wantsRemote]);

  useEffect(() => {
    refresh();
    // Interface enumeration needs a capture backend. When there is none the
    // list is empty and remote mode is the only option — which is exactly the
    // situation remote mode exists for, so the failure is not surfaced.
    getInterfaces().then(setInterfaces).catch(() => setInterfaces([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Poll faster while live so the backlog is close to real time.
  useEffect(() => {
    const t = setInterval(refresh, running ? POLL_MS : POLL_MS * 3);
    return () => clearInterval(t);
  }, [refresh, running]);

  async function toggle() {
    setBusy(true);
    setError(null);
    try {
      let next;
      if (running) {
        next = await stopIngestion();
      } else if (wantsRemote) {
        // No interface: remote mode taps nothing, and the backend refuses an
        // override rather than silently ignoring one.
        next = await startIngestion(undefined, "remote");
      } else {
        next = await startIngestion(selected || undefined);
      }
      setStatus(next);
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Request failed.");
    } finally {
      setBusy(false);
    }
  }

  const capture = status?.capture ?? {};
  const worker = status?.worker ?? {};
  const bridge = status?.bridge?.bridge ?? {};
  const stream = status?.stream ?? {};
  const remote = status?.remote ?? {};
  const uploads = status?.uploads ?? {};
  const ready = preflight?.ready ?? false;

  return (
    <div className="page" style={{ maxWidth: "none" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "1.5rem", gap: "1rem", flexWrap: "wrap" }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)", marginBottom: 4 }}>
            Live Capture
          </h1>
          <p style={{ fontSize: 12, color: "var(--text-secondary)" }}>
            {remoteMode
              ? "Sensors on other hosts submit pcaps; they run through the same agent pipeline as a local capture."
              : "Tap a network interface and feed real traffic through the agent pipeline."}
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.625rem" }}>
          <button className="btn-ghost" onClick={refresh}>
            <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> Refresh
          </button>

          <select
            className="input-base"
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            disabled={running || busy}
            style={{ width: 260, fontSize: 12, padding: "0.5rem 0.75rem" }}
          >
            <optgroup label="Tap this host">
              <option value="">Configured interface</option>
              {interfaces.map((i) => (
                <option key={i.identifier} value={i.identifier}>
                  {i.display_name}
                </option>
              ))}
            </optgroup>
            {/* Not an interface — a mode. Nothing on this host is captured;
                sensors elsewhere submit pcaps to /ingestion/pcap instead. */}
            <optgroup label="Tap another host">
              <option value={REMOTE_OPTION}>Remote sensors (submitted pcaps)</option>
            </optgroup>
          </select>

          <button
            onClick={toggle}
            disabled={busy || (!running && !ready)}
            className={running ? "btn-ghost" : "btn-primary"}
            style={running ? {
              borderColor: "rgba(239,68,68,0.35)", color: "var(--red)", background: "var(--red-dim)",
            } : undefined}
            title={!running && !ready ? "Resolve the blockers below before going live" : undefined}
          >
            {running ? <Square size={12} /> : <Play size={12} />}
            {busy
              ? "Working…"
              : running
                ? (remoteMode ? "Stop Ingest" : "Stop Capture")
                : "Go Live"}
          </button>
        </div>
      </div>

      {/* Live banner */}
      <div className="card" style={{
        padding: "1rem 1.25rem", marginBottom: "1.25rem",
        display: "flex", alignItems: "center", gap: "0.875rem",
        borderColor: running ? "rgba(16,185,129,0.3)" : "var(--border)",
        background: running ? "rgba(16,185,129,0.05)" : "var(--bg-card)",
      }}>
        {running ? (
          <div className="live-dot" style={{ width: 14, height: 14 }}>
            <span className="live-dot-core" style={{ width: 7, height: 7 }} />
          </div>
        ) : remoteMode ? (
          <Cloud size={15} color="var(--text-muted)" />
        ) : (
          <Radio size={15} color="var(--text-muted)" />
        )}
        <div style={{ flex: 1, minWidth: 0 }}>
          <p style={{ fontSize: 13, fontWeight: 600, color: running ? "var(--green)" : "var(--text-secondary)" }}>
            {running
              ? (remoteMode ? "Accepting pcaps from remote sensors" : "Capturing live traffic")
              : (remoteMode ? "Remote ingest stopped" : "Capture stopped")}
          </p>
          <p className="mono" style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 2 }}>
            {remoteMode ? (
              <>
                {remote.endpoint || "/ingestion/pcap"}
                {remote.max_file_mb ? ` · max ${remote.max_file_mb} MB per file` : ""}
                {" · nothing captured on this host"}
              </>
            ) : (
              <>
                {capture.interface || "no interface selected"}
                {capture.snaplen ? ` · snaplen ${capture.snaplen}B (headers only)` : ""}
                {capture.retention_seconds ? ` · retains ${Math.round(capture.retention_seconds / 3600)}h` : ""}
              </>
            )}
          </p>
        </div>
        {running && (() => {
          // Remote mode has no capture handle, so its uptime is the worker's.
          const up = remoteMode
            ? (worker.started_at ? (Date.now() - new Date(worker.started_at)) / 1000 : 0)
            : (capture.uptime_seconds ?? 0);
          return (
            <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
              up {Math.floor(up / 60)}m {Math.round(up % 60)}s
            </span>
          );
        })()}
      </div>

      {error && <Blocker text={error} />}

      {/* Preflight */}
      {!ready && preflight && (
        <Panel title="Preflight — not ready to go live" accent="var(--red)" className="mb-4">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.25rem" }}>
            <div>
              {Object.entries(preflight.checks || {}).map(([name, ok]) => (
                <CheckRow key={name} name={name} ok={ok} />
              ))}
            </div>
            <div>
              {(preflight.blockers || []).map((b, i) => <Blocker key={i} text={b} />)}
            </div>
          </div>
        </Panel>
      )}

      {preflight?.warnings?.length > 0 && (
        <div style={{
          background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.22)",
          borderRadius: "var(--radius)", padding: "0.7rem 0.875rem", marginBottom: "1.25rem",
        }}>
          {preflight.warnings.map((w, i) => (
            <p key={i} style={{ fontSize: 12, color: "#FCD34D", lineHeight: 1.55 }}>{w}</p>
          ))}
        </div>
      )}

      {/* Counters */}
      <div className="grid-cards" style={{ marginBottom: "1.25rem" }}>
        {remoteMode ? (
          <Stat label="Submissions" value={uploads.received ?? 0}
                sub={`${uploads.accepted ?? 0} accepted · ${uploads.mb_received ?? 0} MB`}
                icon={Inbox} tone="#8B5CF6" />
        ) : (
          <Stat label="Capture files" value={capture.file_count ?? 0}
                sub={`${capture.ready_file_count ?? 0} ready · ${capture.total_mb ?? 0} MB`}
                icon={HardDrive} tone="#3B82F6" />
        )}
        <Stat label="Flows published" value={worker.flows_published ?? 0}
              sub={`${worker.files_processed ?? 0} files processed`}
              icon={Layers} tone="#06B6D4" />
        <Stat label="Events through pipeline" value={worker.events_processed ?? 0}
              sub={`${bridge.detections ?? 0} detections · ${bridge.responses ?? 0} responses`}
              icon={Activity} tone="#10B981" />
        <Stat label="Worker errors" value={worker.errors ?? 0}
              sub={worker.last_error ? String(worker.last_error).slice(0, 46) : `${worker.polls ?? 0} polls`}
              icon={ShieldAlert} tone={(worker.errors ?? 0) > 0 ? "#EF4444" : "#64748B"} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.15fr 1fr", gap: "var(--gap)" }} className="lg:grid-cols-2">
        <Panel title="Throughput & Backpressure" accent="var(--cyan)">
          <BacklogBar stream={stream} />
          <div style={{ marginTop: "1.25rem", paddingTop: "1rem", borderTop: "1px solid var(--border)" }}>
            <Row label="Stream reachable" value={stream.reachable ? "yes" : "no"}
                 tone={stream.reachable ? "var(--green)" : "var(--red)"} />
            <Row label="Stream key" value={stream.stream_key} mono />
            <Row label="Consumer group" value={stream.group} mono />
            <Row label="Batch size" value={status?.policy?.batch_size} />
            <Row label="Poll interval" value={`${status?.policy?.poll_interval ?? 0}s`} />
          </div>
        </Panel>

        {remoteMode ? (
          <RemoteIngestPanel
            remote={remote}
            uploads={uploads}
            accepting={remote.accepting ?? false}
            onIngested={refresh}
          />
        ) : (
        <Panel title="Capture Detail" accent="var(--accent)">
          <Row label="Backend" value={capture.backend} />
          <Row label="Interface" value={capture.interface} mono />
          <Row label="Snaplen" value={capture.snaplen ? `${capture.snaplen} bytes` : "—"} />
          <Row label="BPF filter" value={capture.bpf_filter || "none"} mono />
          <Row label="Rotation" value={capture.rotate_seconds ? `every ${capture.rotate_seconds}s` : "—"} />
          <Row label="Retention"
               value={capture.retention_seconds ? `${capture.retain_files} files · ${Math.round(capture.retention_seconds / 3600)}h` : "—"} />
          <Row label="Active file" value={capture.active_file || "—"} mono />
          <Row label="Output" value={capture.output_dir} mono />
          <Row label="Policy source" value={status?.policy?.source} mono />
          {capture.warnings?.length > 0 && (
            <p style={{ fontSize: 11, color: "var(--yellow)", marginTop: 10, lineHeight: 1.5 }}>
              {capture.warnings.join(" ")}
            </p>
          )}
        </Panel>
        )}
      </div>
    </div>
  );
}

function Row({ label, value, mono, tone }) {
  return (
    <div style={{
      display: "flex", justifyContent: "space-between", alignItems: "center",
      gap: "1rem", padding: "0.4rem 0",
    }}>
      <span style={{ fontSize: 12, color: "var(--text-secondary)", flexShrink: 0 }}>{label}</span>
      <span
        className={mono ? "mono" : undefined}
        style={{
          fontSize: 12, color: tone || "var(--text-primary)",
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          maxWidth: "62%", textAlign: "right",
        }}
        title={value == null ? "—" : String(value)}
      >
        {value == null || value === "" ? "—" : String(value)}
      </span>
    </div>
  );
}
