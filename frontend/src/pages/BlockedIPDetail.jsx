import { ArrowLeft, RefreshCw, ShieldX } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useApi } from "../hooks/useApi";
import { getBlockedIps } from "../api/blockedIpsApi";

function Row({ label, value }) {
  return (
    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"0.5rem 0", borderBottom:"1px solid var(--border)" }}>
      <span style={{ fontSize:11, color:"var(--text-secondary)" }}>{label}</span>
      <span style={{ fontSize:12, fontWeight:500, color:"var(--text-primary)" }}>{value}</span>
    </div>
  );
}

export default function BlockedIPDetail() {
  const { id } = useParams();
  const { data, loading, error, refetch } = useApi(getBlockedIps);
  const ip = (data ?? []).find((item) => String(item.id) === id);

  return (
    <div className="page">
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"1.5rem", flexWrap:"wrap", gap:"0.75rem" }}>
        <div style={{ display:"flex", alignItems:"center", gap:"0.75rem" }}>
          <Link to="/blocked" style={{
            display:"inline-flex", alignItems:"center", gap:4,
            fontSize:12, color:"var(--text-secondary)",
            padding:"0.35rem 0.625rem",
            borderRadius:"var(--radius-sm)",
            border:"1px solid var(--border)",
            background:"var(--bg-card)",
          }}>
            <ArrowLeft size={12} /> Blocked IPs
          </Link>
          <h1 style={{ fontSize:16, fontWeight:700, color:"var(--text-primary)" }}>
            Blocked IP Details
          </h1>
        </div>
        <button className="btn-ghost" onClick={refetch}>
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
        </button>
      </div>

      {error && (
        <div style={{ background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.25)", borderRadius:"var(--radius)", padding:"0.75rem 1rem", fontSize:12, color:"#FCA5A5", marginBottom:"1rem" }}>
          {error}
        </div>
      )}

      {loading ? (
        <div className="grid-2">
          {[0,1].map((i) => <div key={i} className="skeleton" style={{ height:240 }} />)}
        </div>
      ) : !ip ? (
        <div className="card" style={{ padding:"2rem", textAlign:"center" }}>
          <ShieldX size={32} color="var(--text-muted)" style={{ margin:"0 auto 0.75rem" }} />
          <p style={{ fontSize:13, color:"var(--text-secondary)" }}>No record found for ID "{id}".</p>
          <Link to="/blocked" style={{ display:"inline-block", marginTop:"1rem", fontSize:12, color:"var(--accent-bright)" }}>
            ← Back to Blocked IPs
          </Link>
        </div>
      ) : (
        <div className="grid-2">
          <div className="card" style={{ padding:"1.25rem" }}>
            <h2 style={{ fontSize:13, fontWeight:600, color:"var(--text-primary)", marginBottom:"1rem", paddingBottom:"0.75rem", borderBottom:"1px solid var(--border)" }}>
              IP Information
            </h2>
            <div style={{ display:"flex", flexDirection:"column", gap:"0.125rem" }}>
              <Row label="IP Address" value={<span className="mono" style={{ fontSize:12, color:"#FCA5A5" }}>{ip.ip}</span>} />
              <Row label="Reason"     value={ip.reason} />
              <Row label="Blocked At" value={new Date(ip.blocked_at).toLocaleString()} />
              <Row label="Status"     value={<span style={{ color:"#FCA5A5", fontWeight:600 }}>Active</span>} />
            </div>
          </div>

          <div className="card" style={{ padding:"1.25rem" }}>
            <h2 style={{ fontSize:13, fontWeight:600, color:"var(--text-primary)", marginBottom:"1rem", paddingBottom:"0.75rem", borderBottom:"1px solid var(--border)" }}>
              Recommended Actions
            </h2>
            <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
              {[
                "Firewall rule verified",
                "Threat intelligence updated",
                "Notify SOC analyst",
                "Continue monitoring",
              ].map((item) => (
                <div key={item} style={{
                  display:"flex", alignItems:"center", gap:8,
                  padding:"0.625rem 0.75rem",
                  background:"var(--bg-base)", borderRadius:"var(--radius-sm)",
                  border:"1px solid var(--border)", fontSize:12, color:"var(--text-primary)",
                }}>
                  <span style={{ color:"var(--green)" }}>✓</span> {item}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
