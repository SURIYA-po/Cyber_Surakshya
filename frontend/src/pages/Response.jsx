import { useCallback, useEffect, useState } from "react";
import {
  ShieldCheck, RefreshCw, Check, X, Clock, Ban, Shield,
  AlertTriangle, Cpu, Zap,
} from "lucide-react";
import Panel from "../components/common/Panel";
import {
  getResponseActions, getPendingApprovals, getResponsePolicy,
  approveAction, rejectAction,
} from "../api/responseApi";

/** Status → colour. These mirror ResponseStatus in the backend schema. */
const STATUS_TONE = {
  EXECUTED:          "#10B981",
  DRY_RUN:           "#06B6D4",
  AWAITING_APPROVAL: "#F59E0B",
  BLOCKED_BY_GUARD:  "#EF4444",
  DOWNGRADED:        "#F97316",
  DEDUPLICATED:      "#64748B",
  NO_OP:             "#64748B",
  FAILED:            "#EF4444",
  REVERTED:          "#8B5CF6",
};

const TIER_TONE = {
  DETERMINISTIC: "#10B981",
  AI_SUPERVISED: "#F59E0B",
  AI_AUTONOMOUS: "#F97316",
  UNKNOWN:       "#EF4444",
};

function Pill({ text, tone }) {
  return (
    <span style={{
      display: "inline-block", padding: "0.15rem 0.5rem", borderRadius: 999,
      fontSize: 10, fontWeight: 600, letterSpacing: "0.02em",
      color: tone, background: `${tone}18`, border: `1px solid ${tone}33`,
      whiteSpace: "nowrap",
    }}>
      {text}
    </span>
  );
}

function Stat({ label, value, icon: Icon, tone }) {
  return (
    <div className="card" style={{ padding: "1rem 1.125rem" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <p style={{ fontSize: 11, color: "var(--text-secondary)" }}>{label}</p>
        <Icon size={13} color={tone} />
      </div>
      <p style={{ fontSize: 22, fontWeight: 700, color: "var(--text-primary)" }}>{value}</p>
    </div>
  );
}

/**
 * One item in the human-in-the-loop queue.
 *
 * These exist because something refused to self-authorise: either the policy
 * demanded approval, or the decision came from an engine whose trust tier
 * forbids it acting alone. An LLM cannot approve its own destructive action.
 */
function ApprovalCard({ item, onApprove, onReject, busy }) {
  return (
    <div className="card" style={{ padding: "1rem 1.125rem", marginBottom: "0.75rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: "1rem", marginBottom: 10 }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5, flexWrap: "wrap" }}>
            <strong style={{ fontSize: 13, color: "var(--text-primary)" }}>{item.action_type}</strong>
            <span className="mono" style={{ fontSize: 11, color: "var(--accent-bright)" }}>
              {item.target_value}
            </span>
            <Pill text={item.engine_trust_tier} tone={TIER_TONE[item.engine_trust_tier] || "#64748B"} />
          </div>
          <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.55 }}>
            {item.guard_reason}
          </p>
          <p className="mono" style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 6 }}>
            rule {item.guard_rule} · engine {item.decision_engine} · decision {String(item.decision_id).slice(0, 8)}
          </p>
        </div>
        <div style={{ display: "flex", gap: 6, flexShrink: 0, alignItems: "flex-start" }}>
          <button
            className="btn-primary"
            disabled={busy}
            onClick={() => onApprove(item.decision_id)}
            style={{ background: "var(--green)", padding: "0.4rem 0.75rem", fontSize: 12 }}
          >
            <Check size={12} /> Approve
          </button>
          <button
            className="btn-ghost"
            disabled={busy}
            onClick={() => onReject(item.decision_id)}
            style={{ color: "var(--red)", borderColor: "rgba(239,68,68,0.3)", padding: "0.4rem 0.75rem", fontSize: 12 }}
          >
            <X size={12} /> Reject
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Response() {
  const [actions, setActions] = useState([]);
  const [pending, setPending] = useState([]);
  const [policy, setPolicy] = useState(null);
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [toast, setToast] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [a, p, pol] = await Promise.all([
        getResponseActions(filter || undefined),
        getPendingApprovals(),
        getResponsePolicy().catch(() => null),
      ]);
      setActions(a); setPending(p); setPolicy(pol); setError(null);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    const t = setInterval(refresh, 8000);
    return () => clearInterval(t);
  }, [refresh]);

  async function rule(decisionId, approve) {
    setBusy(true);
    try {
      await (approve ? approveAction : rejectAction)(decisionId, "analyst");
      setToast(`${approve ? "Approved" : "Rejected"} ${String(decisionId).slice(0, 8)} — takes effect on the next pipeline run.`);
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setBusy(false);
      setTimeout(() => setToast(null), 6000);
    }
  }

  const counts = actions.reduce((acc, a) => {
    acc[a.status] = (acc[a.status] || 0) + 1;
    return acc;
  }, {});
  const guardStopped = (counts.BLOCKED_BY_GUARD || 0) + (counts.DOWNGRADED || 0);

  return (
    <div className="page" style={{ maxWidth: "none" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "1.5rem", gap: "1rem", flexWrap: "wrap" }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)", marginBottom: 4 }}>
            Response
          </h1>
          <p style={{ fontSize: 12, color: "var(--text-secondary)" }}>
            What the platform did, and what it is waiting on you to authorise.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.625rem", alignItems: "center" }}>
          <select
            className="input-base"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{ width: 190, fontSize: 12, padding: "0.5rem 0.75rem" }}
          >
            <option value="">All statuses</option>
            {Object.keys(STATUS_TONE).map((s) => (
              <option key={s} value={s}>{s.replace(/_/g, " ")}</option>
            ))}
          </select>
          <button className="btn-ghost" onClick={refresh}>
            <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      {toast && (
        <div style={{
          background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.25)",
          borderRadius: "var(--radius)", padding: "0.7rem 0.875rem", marginBottom: "1rem",
          fontSize: 12, color: "#6EE7B7",
        }}>{toast}</div>
      )}
      {error && (
        <div style={{
          background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)",
          borderRadius: "var(--radius)", padding: "0.7rem 0.875rem", marginBottom: "1rem",
          fontSize: 12, color: "#FCA5A5",
        }}>{error}</div>
      )}

      <div className="grid-cards" style={{ marginBottom: "1.5rem" }}>
        <Stat label="Awaiting approval" value={pending.length} icon={Clock}
              tone={pending.length ? "#F59E0B" : "#64748B"} />
        <Stat label="Executed" value={counts.EXECUTED || 0} icon={ShieldCheck} tone="#10B981" />
        <Stat label="Stopped by guard" value={guardStopped} icon={Shield} tone="#F97316" />
        <Stat label="Failed" value={counts.FAILED || 0} icon={AlertTriangle}
              tone={(counts.FAILED || 0) ? "#EF4444" : "#64748B"} />
      </div>

      {/* HITL queue */}
      <Panel
        title={`Approval Queue (${pending.length})`}
        accent="var(--yellow)"
        className="mb-4"
      >
        {pending.length === 0 ? (
          <p style={{ fontSize: 12, color: "var(--text-secondary)", padding: "0.5rem 0" }}>
            Nothing is waiting on a human. Actions reach this queue when policy requires
            approval, or when the decision engine's trust tier forbids it acting alone.
          </p>
        ) : (
          <>
            <p style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: "0.875rem", lineHeight: 1.55 }}>
              Approving records your ruling; the action executes on the next pipeline run.
              Rejecting is terminal.
            </p>
            {pending.map((item) => (
              <ApprovalCard
                key={item.response_id}
                item={item}
                busy={busy}
                onApprove={(id) => rule(id, true)}
                onReject={(id) => rule(id, false)}
              />
            ))}
          </>
        )}
      </Panel>

      <div style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: "var(--gap)" }} className="lg:grid-cols-2">
        {/* Action history */}
        <Panel title={`Response Actions (${actions.length})`} accent="var(--accent)">
          {actions.length === 0 ? (
            <p style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              No response actions recorded yet.
            </p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border)" }}>
                    {["Action", "Target", "Status", "Guard", "Trust", "Executor"].map((h) => (
                      <th key={h} style={{
                        textAlign: "left", padding: "0.5rem 0.625rem",
                        fontSize: 10, fontWeight: 600, letterSpacing: "0.06em",
                        textTransform: "uppercase", color: "var(--text-muted)",
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {actions.slice(0, 60).map((a) => (
                    <tr key={a.response_id} className="trow" style={{ borderBottom: "1px solid var(--border)" }}>
                      <td style={{ padding: "0.55rem 0.625rem", color: "var(--text-primary)", whiteSpace: "nowrap" }}>
                        {a.action_type}
                        {a.original_action_type && a.original_action_type !== a.action_type && (
                          <span style={{ color: "var(--text-muted)", fontSize: 10 }}> ← {a.original_action_type}</span>
                        )}
                      </td>
                      <td className="mono" style={{ padding: "0.55rem 0.625rem", color: "var(--accent-bright)" }}>
                        {a.target_value}
                      </td>
                      <td style={{ padding: "0.55rem 0.625rem" }}>
                        <Pill text={a.status} tone={STATUS_TONE[a.status] || "#64748B"} />
                      </td>
                      <td style={{ padding: "0.55rem 0.625rem", color: "var(--text-secondary)", maxWidth: 190, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                          title={a.guard_reason}>
                        {a.guard_rule}
                      </td>
                      <td style={{ padding: "0.55rem 0.625rem" }}>
                        <Pill text={a.engine_trust_tier} tone={TIER_TONE[a.engine_trust_tier] || "#64748B"} />
                      </td>
                      <td style={{ padding: "0.55rem 0.625rem", color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
                        {a.executor_name || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* Authorisation policy */}
        <Panel title="Authorisation Policy" accent="var(--purple)">
          {!policy ? (
            <p style={{ fontSize: 12, color: "var(--text-secondary)" }}>Policy unavailable.</p>
          ) : (
            <>
              <p style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: "0.875rem", lineHeight: 1.55 }}>
                The rules that decide whether a decision may execute unassisted.
                Engines not listed here are untrusted and always downgraded.
              </p>

              <p className="section-title" style={{ fontSize: 10, marginBottom: 6 }}>Engine trust</p>
              {Object.entries(policy.engine_trust || {}).map(([engine, tier]) => (
                <div key={engine} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "0.35rem 0", gap: 8,
                }}>
                  <span className="mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>{engine}</span>
                  <Pill text={tier} tone={TIER_TONE[tier] || "#64748B"} />
                </div>
              ))}

              <div style={{ marginTop: "1rem", paddingTop: "0.875rem", borderTop: "1px solid var(--border)" }}>
                <p className="section-title" style={{ fontSize: 10, marginBottom: 6 }}>Blast radius</p>
                <Line label="Per workflow" value={policy.blast_radius?.max_destructive_per_correlation} />
                <Line label="Per target window" value={`${policy.blast_radius?.max_destructive_per_target_window_seconds}s`} />
                <Line label="Circuit breaker" value={`${policy.blast_radius?.global_destructive_per_minute}/min`} />
                <Line label="Dry run" value={policy.dry_run ? "ON — nothing executes" : "off"}
                      tone={policy.dry_run ? "var(--yellow)" : undefined} />
                <Line label="Downgrades to" value={policy.downgrade_action} />
              </div>

              <div style={{ marginTop: "1rem", paddingTop: "0.875rem", borderTop: "1px solid var(--border)" }}>
                <p className="section-title" style={{ fontSize: 10, marginBottom: 6 }}>
                  Protected ranges ({policy.protected_cidrs?.length || 0})
                </p>
                <p className="mono" style={{ fontSize: 10, color: "var(--text-secondary)", lineHeight: 1.7, wordBreak: "break-all" }}>
                  {(policy.protected_cidrs || []).join("  ")}
                </p>
              </div>
            </>
          )}
        </Panel>
      </div>
    </div>
  );
}

function Line({ label, value, tone }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", padding: "0.3rem 0" }}>
      <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{label}</span>
      <span style={{ fontSize: 12, color: tone || "var(--text-primary)" }}>{value ?? "—"}</span>
    </div>
  );
}
