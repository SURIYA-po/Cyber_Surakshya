import { Server } from "lucide-react";
import Panel from "../common/Panel";
import { useApi } from "../../hooks/useApi";
import { getAgents } from "../../api/agentsApi";

const STATUS = {
  ONLINE:  { color:"var(--green)",  label:"Online"  },
  OFFLINE: { color:"var(--red)",    label:"Offline" },
  BUSY:    { color:"var(--yellow)", label:"Busy"    },
};

function timeAgo(iso) {
  const d = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (d < 10)  return "just now";
  if (d < 60)  return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d/60)}m ago`;
  return `${Math.floor(d/3600)}h ago`;
}

export default function AgentHealth() {
  const { data, loading } = useApi(getAgents);
  const agents = data ?? [];

  return (
    <Panel title="Agent Health" accent="#10B981">
      {loading ? (
        <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
          {[0,1,2].map((i) => <div key={i} className="skeleton" style={{ height:52 }} />)}
        </div>
      ) : (
        <div style={{ display:"flex", flexDirection:"column", gap:"0.5rem" }}>
          {agents.map((agent) => {
            const s = STATUS[agent.status] ?? STATUS.OFFLINE;
            const isOnline = agent.status === "ONLINE";
            return (
              <div key={agent.id} style={{
                display:"flex", alignItems:"center", justifyContent:"space-between",
                padding:"0.625rem 0.75rem",
                borderRadius:"var(--radius)",
                background:"var(--bg-base)",
                border:"1px solid var(--border)",
              }}>
                <div style={{ display:"flex", alignItems:"center", gap:"0.5rem" }}>
                  <Server size={13} color="var(--cyan)" />
                  <div>
                    <p style={{ fontSize:12, fontWeight:500, color:"var(--text-primary)" }}>{agent.agent_name}</p>
                    <p style={{ fontSize:10, color:"var(--text-secondary)", marginTop:1 }}>
                      {timeAgo(agent.heartbeat)}
                    </p>
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                  <span style={{ width:6, height:6, borderRadius:"50%", background:s.color, flexShrink:0 }} />
                  <span style={{ fontSize:11, color:s.color, fontWeight:500 }}>{s.label}</span>
                </div>
              </div>
            );
          })}
          {agents.length === 0 && (
            <p style={{ fontSize:12, color:"var(--text-secondary)", textAlign:"center", padding:"1.5rem 0" }}>
              No agents registered.
            </p>
          )}
        </div>
      )}
    </Panel>
  );
}
