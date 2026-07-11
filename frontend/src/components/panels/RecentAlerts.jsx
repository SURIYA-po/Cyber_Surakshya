import { Link } from "react-router-dom";
import { ShieldAlert, ArrowRight } from "lucide-react";
import Panel from "../common/Panel";
import { useLiveFeed } from "../../hooks/useLiveFeed";
import { useApi } from "../../hooks/useApi";
import { getAlerts } from "../../api/alertsApi";

const SEV_COLOR = {
  CRITICAL:"#FCA5A5", HIGH:"#FDBA74", MEDIUM:"#FCD34D", LOW:"#6EE7B7",
};

export default function RecentAlerts() {
  const { data } = useApi(getAlerts);
  const { alerts:live, connected } = useLiveFeed(5);

  const base = (data ?? []).slice(0,5);
  const liveIds = new Set(live.map((a) => a.id));
  const merged = [...live, ...base.filter((a) => !liveIds.has(a.id))].slice(0,5);

  const liveIndicator = (
    <div style={{ display:"flex", alignItems:"center", gap:5 }}>
      {connected ? (
        <div className="live-dot" style={{ width:10, height:10 }}>
          <span className="live-dot-core" style={{ width:5, height:5 }} />
        </div>
      ) : (
        <span style={{ width:5, height:5, borderRadius:"50%", background:"var(--red)", display:"inline-block" }} />
      )}
      <span style={{ fontSize:10, color: connected ? "var(--green)" : "var(--text-secondary)", fontWeight:600 }}>
        {connected ? "LIVE" : "offline"}
      </span>
    </div>
  );

  return (
    <Panel title="Recent Alerts" accent="#EF4444" action={liveIndicator}>
      <div style={{ display:"flex", flexDirection:"column", gap:"0.625rem" }}>
        {merged.length === 0 && (
          <p style={{ fontSize:12, color:"var(--text-secondary)", textAlign:"center", padding:"2rem 0" }}>
            No alerts yet — run a simulation.
          </p>
        )}
        {merged.map((alert) => (
          <div key={alert.id} style={{
            display:"flex", alignItems:"center", justifyContent:"space-between",
            padding:"0.625rem 0.75rem",
            borderRadius:"var(--radius)",
            background:"var(--bg-base)",
            border:"1px solid var(--border)",
            gap:"0.75rem",
            transition:"border-color 0.12s",
          }}>
            <div style={{ display:"flex", alignItems:"center", gap:"0.625rem", minWidth:0 }}>
              <ShieldAlert size={14} color={SEV_COLOR[alert.severity] ?? "#94A3B8"} style={{ flexShrink:0 }} />
              <div style={{ minWidth:0 }}>
                <p style={{ fontSize:12, fontWeight:500, color:"var(--text-primary)", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
                  {alert.attack_type}
                </p>
                <p className="mono" style={{ fontSize:10, color:"var(--text-secondary)", marginTop:1 }}>
                  {alert.source_ip}
                </p>
              </div>
            </div>
            <div style={{ display:"flex", alignItems:"center", gap:"0.5rem", flexShrink:0 }}>
              <span style={{
                fontSize:10, fontWeight:600, padding:"2px 6px", borderRadius:20,
                color: SEV_COLOR[alert.severity] ?? "#94A3B8",
                background:`${SEV_COLOR[alert.severity] ?? "#94A3B8"}18`,
              }}>
                {alert.severity}
              </span>
              <Link to={`/alerts/${alert.id}`} style={{
                display:"inline-flex", alignItems:"center", justifyContent:"center",
                width:22, height:22, borderRadius:"var(--radius-sm)",
                background:"var(--accent-dim)", border:"1px solid var(--border-accent)",
                color:"var(--accent-bright)",
              }}>
                <ArrowRight size={10} />
              </Link>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}
