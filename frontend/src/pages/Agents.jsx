import { RefreshCw, Server, Clock, Wifi, WifiOff } from "lucide-react";
import { useApi } from "../hooks/useApi";
import { getAgents } from "../api/agentsApi";

const STATUS = {
  ONLINE:  { color:"#10B981", dim:"rgba(16,185,129,0.1)", border:"rgba(16,185,129,0.25)", label:"Online" },
  OFFLINE: { color:"#EF4444", dim:"rgba(239,68,68,0.1)",  border:"rgba(239,68,68,0.25)",  label:"Offline" },
  BUSY:    { color:"#F59E0B", dim:"rgba(245,158,11,0.1)", border:"rgba(245,158,11,0.25)", label:"Busy" },
};

function timeAgo(iso) {
  const d = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (d < 10) return "just now";
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d/60)}m ago`;
  return `${Math.floor(d/3600)}h ago`;
}

function SummaryCard({ label, value, color }) {
  return (
    <div className="card" style={{ padding:"1rem 1.25rem" }}>
      <p style={{ fontSize:11, color:"var(--text-secondary)", marginBottom:6 }}>{label}</p>
      <p style={{ fontSize:26, fontWeight:700, color: color ?? "var(--text-primary)" }}>{value}</p>
    </div>
  );
}

export default function Agents() {
  const { data, loading, error, refetch } = useApi(getAgents);
  const agents = data ?? [];
  const online = agents.filter((a) => a.status === "ONLINE").length;

  return (
    <div className="page">
      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:"1.5rem" }}>
        <div>
          <h1 style={{ fontSize:20, fontWeight:700, color:"var(--text-primary)", marginBottom:4 }}>Agent Monitoring</h1>
          <p style={{ fontSize:12, color:"var(--text-secondary)" }}>Live health and status for every backend agent.</p>
        </div>
        <button className="btn-ghost" onClick={refetch}>
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Summary */}
      <div className="grid-3" style={{ marginBottom:"1.5rem" }}>
        <SummaryCard label="Total Agents"   value={agents.length} />
        <SummaryCard label="Online"         value={`${online}/${agents.length}`} color="#10B981" />
        <SummaryCard label="Offline / Busy" value={agents.length - online}       color={agents.length-online>0?"#EF4444":undefined} />
      </div>

      {error && (
        <div style={{ background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.25)", borderRadius:"var(--radius)", padding:"0.75rem 1rem", fontSize:12, color:"#FCA5A5", marginBottom:"1rem" }}>
          {error}
        </div>
      )}

      {/* Agent grid */}
      {loading ? (
        <div className="grid-agents">
          {[0,1,2,3].map((i) => <div key={i} className="skeleton" style={{ height:160 }} />)}
        </div>
      ) : (
        <div className="grid-agents">
          {agents.map((agent) => {
            const s = STATUS[agent.status] ?? STATUS.OFFLINE;
            return (
              <div key={agent.id} className="card" style={{
                padding:"1.25rem",
                borderColor: agent.status==="ONLINE" ? "rgba(16,185,129,0.2)" : "var(--border)",
                transition:"border-color 0.2s",
              }}>
                {/* Header */}
                <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"1rem" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:"0.625rem" }}>
                    <div style={{
                      width:32, height:32, borderRadius:"var(--radius-sm)",
                      background:"rgba(6,182,212,0.1)", border:"1px solid rgba(6,182,212,0.2)",
                      display:"flex", alignItems:"center", justifyContent:"center",
                    }}>
                      <Server size={14} color="var(--cyan)" />
                    </div>
                    <div>
                      <p style={{ fontSize:13, fontWeight:600, color:"var(--text-primary)" }}>{agent.agent_name}</p>
                      <p style={{ fontSize:10, color:"var(--text-secondary)" }}>Agent #{agent.id}</p>
                    </div>
                  </div>
                  <span style={{
                    display:"inline-flex", alignItems:"center", gap:5,
                    padding:"3px 8px", borderRadius:20, fontSize:10, fontWeight:600,
                    background:s.dim, border:`1px solid ${s.border}`, color:s.color,
                  }}>
                    <span style={{ width:5, height:5, borderRadius:"50%", background:s.color }} />
                    {s.label}
                  </span>
                </div>

                {/* Heartbeat bar */}
                <div style={{ marginBottom:"0.875rem" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                    <span style={{ fontSize:10, color:"var(--text-secondary)" }}>Heartbeat</span>
                    <span style={{ fontSize:10, fontWeight:600, color: agent.status==="ONLINE" ? "#10B981" : "#EF4444" }}>
                      {agent.status === "ONLINE" ? "100%" : "0%"}
                    </span>
                  </div>
                  <div style={{ height:4, borderRadius:99, background:"var(--bg-base)" }}>
                    <div style={{
                      height:"100%", borderRadius:99,
                      width: agent.status==="ONLINE" ? "100%" : "0%",
                      background: agent.status==="ONLINE" ? "#10B981" : "#EF4444",
                      transition:"width 0.6s ease",
                    }} />
                  </div>
                </div>

                {/* Last seen */}
                <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                  <Clock size={10} color="var(--text-muted)" />
                  <span style={{ fontSize:10, color:"var(--text-secondary)" }}>
                    Last heartbeat: {timeAgo(agent.heartbeat)}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
