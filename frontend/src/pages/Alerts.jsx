import { useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import SearchBar from "../components/alerts/SearchBar";
import FilterBar from "../components/alerts/FilterBar";
import AlertTable from "../components/alerts/AlertTable";
import { useApi } from "../hooks/useApi";
import { getAlerts } from "../api/alertsApi";

function norm(a) {
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
  return {
    id: String(a.id),
    attackType: a.attack_type,
    sourceIp: a.source_ip,
    severity: cap(a.severity),
    status: cap(a.status),
    time: new Date(a.created_at).toLocaleString(),
  };
}

function SummaryCard({ label, value, borderColor }) {
  return (
    <div style={{
      background:"var(--bg-card)", borderRadius:"var(--radius-lg)",
      border:`1px solid ${borderColor}`, padding:"1rem 1.25rem",
    }}>
      <p style={{ fontSize:11, color:"var(--text-secondary)", marginBottom:6 }}>{label}</p>
      <p style={{ fontSize:26, fontWeight:700, color:"var(--text-primary)" }}>{value}</p>
    </div>
  );
}

export default function Alerts() {
  const { data, loading, error, refetch } = useApi(getAlerts);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("All");
  const [status, setStatus] = useState("All");

  const alerts = useMemo(() => (data ?? []).map(norm), [data]);
  const filtered = useMemo(() => alerts.filter((a) => {
    const s = search.toLowerCase();
    return (
      (a.id.includes(s) || a.attackType.toLowerCase().includes(s) || a.sourceIp.includes(s)) &&
      (severity === "All" || a.severity === severity) &&
      (status === "All" || a.status === status)
    );
  }), [alerts, search, severity, status]);

  return (
    <div className="page">
      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:"1.5rem" }}>
        <div>
          <h1 style={{ fontSize:20, fontWeight:700, color:"var(--text-primary)", marginBottom:4 }}>Alerts</h1>
          <p style={{ fontSize:12, color:"var(--text-secondary)" }}>View, search and investigate security alerts.</p>
        </div>
        <button className="btn-ghost" onClick={refetch}>
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Summary */}
      <div className="grid-cards-sm" style={{ marginBottom:"1.5rem" }}>
        <SummaryCard label="Total Alerts"  value={alerts.length}                                                       borderColor="var(--border)" />
        <SummaryCard label="Critical"      value={alerts.filter((a) => a.severity==="Critical").length}                borderColor="rgba(239,68,68,0.3)" />
        <SummaryCard label="Investigating" value={alerts.filter((a) => a.status==="Investigating").length}             borderColor="rgba(245,158,11,0.3)" />
        <SummaryCard label="Resolved"      value={alerts.filter((a) => a.status==="Resolved").length}                 borderColor="rgba(16,185,129,0.3)" />
      </div>

      {/* Controls */}
      <div style={{ display:"flex", alignItems:"center", gap:"0.75rem", flexWrap:"wrap", marginBottom:"1rem" }}>
        <SearchBar searchTerm={search} setSearchTerm={setSearch} />
        <FilterBar severity={severity} setSeverity={setSeverity} status={status} setStatus={setStatus} />
      </div>

      {error && (
        <div style={{
          background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.25)",
          borderRadius:"var(--radius)", padding:"0.75rem 1rem",
          fontSize:12, color:"#FCA5A5", marginBottom:"1rem",
        }}>{error}</div>
      )}

      {/* Table card */}
      <div className="card" style={{ padding:"1.25rem" }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"1rem" }}>
          <h2 style={{ fontSize:14, fontWeight:600, color:"var(--text-primary)" }}>Security Alerts</h2>
          <span style={{ fontSize:11, color:"var(--text-secondary)" }}>
            {filtered.length} of {alerts.length} alerts
          </span>
        </div>

        {loading ? (
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {Array.from({length:5}).map((_,i) => (
              <div key={i} className="skeleton" style={{ height:44 }} />
            ))}
          </div>
        ) : (
          <AlertTable alerts={filtered} />
        )}
      </div>
    </div>
  );
}
