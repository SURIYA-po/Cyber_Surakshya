import { useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import SearchBar from "../components/blockedIps/SearchBar";
import FilterBar from "../components/blockedIps/FilterBar";
import BlockedIpTable from "../components/blockedIps/BlockedIpTable";
import { useApi } from "../hooks/useApi";
import { getBlockedIps } from "../api/blockedIpsApi";

function norm(ip) {
  return {
    id:ip.id, ip:ip.ip, country:"—",
    reason:ip.reason,
    severity:"High", status:"Active",
    blockedAt:new Date(ip.blocked_at).toLocaleString(),
  };
}

function SummaryCard({ label, value, color }) {
  return (
    <div className="card" style={{ padding:"1rem 1.25rem" }}>
      <p style={{ fontSize:11, color:"var(--text-secondary)", marginBottom:6 }}>{label}</p>
      <p style={{ fontSize:26, fontWeight:700, color: color ?? "var(--text-primary)" }}>{value}</p>
    </div>
  );
}

export default function BlockedIPs() {
  const { data, loading, error, refetch } = useApi(getBlockedIps);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("All");
  const [status, setStatus] = useState("All");

  const ips = useMemo(() => (data ?? []).map(norm), [data]);
  const filtered = useMemo(() => ips.filter((ip) => {
    const s = search.toLowerCase();
    return (
      (ip.ip.includes(s) || ip.country.toLowerCase().includes(s) || ip.reason.toLowerCase().includes(s)) &&
      (severity==="All" || ip.severity===severity) &&
      (status==="All" || ip.status===status)
    );
  }), [ips, search, severity, status]);

  return (
    <div className="page">
      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:"1.5rem" }}>
        <div>
          <h1 style={{ fontSize:20, fontWeight:700, color:"var(--text-primary)", marginBottom:4 }}>Blocked IPs</h1>
          <p style={{ fontSize:12, color:"var(--text-secondary)" }}>All IP addresses blocked by the SOC platform.</p>
        </div>
        <button className="btn-ghost" onClick={refetch}>
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      <div className="grid-cards-sm" style={{ marginBottom:"1.5rem" }}>
        <SummaryCard label="Total Blocked"  value={ips.length} />
        <SummaryCard label="Active Blocks"  value={ips.filter((i)=>i.status==="Active").length}  color="#EF4444" />
        <SummaryCard label="Unique IPs"     value={[...new Set(ips.map((i)=>i.ip))].length}      color="#3B82F6" />
        <SummaryCard label="Critical"       value={ips.filter((i)=>i.severity==="Critical").length} color="#F59E0B" />
      </div>

      <div style={{ display:"flex", alignItems:"center", gap:"0.75rem", flexWrap:"wrap", marginBottom:"1rem" }}>
        <SearchBar searchTerm={search} setSearchTerm={setSearch} />
        <FilterBar severity={severity} setSeverity={setSeverity} status={status} setStatus={setStatus} />
      </div>

      {error && (
        <div style={{ background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.25)", borderRadius:"var(--radius)", padding:"0.75rem 1rem", fontSize:12, color:"#FCA5A5", marginBottom:"1rem" }}>
          {error}
        </div>
      )}

      <div className="card" style={{ padding:"1.25rem" }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"1rem" }}>
          <h2 style={{ fontSize:14, fontWeight:600, color:"var(--text-primary)" }}>Blocked IP List</h2>
          <span style={{ fontSize:11, color:"var(--text-secondary)" }}>{filtered.length} records</span>
        </div>
        {loading ? (
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {Array.from({length:5}).map((_,i) => <div key={i} className="skeleton" style={{ height:44 }} />)}
          </div>
        ) : (
          <BlockedIpTable blockedIps={filtered} />
        )}
      </div>
    </div>
  );
}
