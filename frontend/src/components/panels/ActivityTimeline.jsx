import Panel from "../common/Panel";
import { useApi } from "../../hooks/useApi";
import { getAlerts } from "../../api/alertsApi";

const SEV_DOT = { CRITICAL:"#EF4444", HIGH:"#F97316", MEDIUM:"#F59E0B", LOW:"#10B981" };

export default function ActivityTimeline() {
  const { data } = useApi(getAlerts);
  const alerts = (data ?? []).slice(0, 8);

  return (
    <Panel title="Activity Timeline" accent="#8B5CF6">
      {alerts.length === 0 ? (
        <p style={{ fontSize:12, color:"var(--text-secondary)", padding:"1rem 0" }}>No activity yet.</p>
      ) : (
        <div style={{ position:"relative" }}>
          {/* vertical line */}
          <div style={{
            position:"absolute", left:7, top:8, bottom:8, width:1,
            background:"var(--border-strong)",
          }} />

          <div style={{ display:"flex", flexDirection:"column", gap:"0.875rem" }}>
            {alerts.map((alert) => (
              <div key={alert.id} style={{ display:"flex", gap:"1rem", paddingLeft:"1.25rem", position:"relative" }}>
                <span style={{
                  position:"absolute", left:2, top:4,
                  width:11, height:11, borderRadius:"50%",
                  background:SEV_DOT[alert.severity] ?? "#64748B",
                  border:"2px solid var(--bg-card)",
                  flexShrink:0,
                }} />
                <div style={{ minWidth:0, flex:1 }}>
                  <div style={{ display:"flex", alignItems:"baseline", justifyContent:"space-between", gap:8 }}>
                    <p style={{ fontSize:12, fontWeight:500, color:"var(--text-primary)" }}>
                      {alert.attack_type}
                    </p>
                    <span style={{ fontSize:10, color:"var(--text-secondary)", flexShrink:0 }}>
                      {new Date(alert.created_at).toLocaleTimeString([], { hour:"2-digit", minute:"2-digit" })}
                    </span>
                  </div>
                  <p className="mono" style={{ fontSize:10, color:"var(--text-secondary)", marginTop:1 }}>
                    {alert.source_ip} · {alert.severity}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}
