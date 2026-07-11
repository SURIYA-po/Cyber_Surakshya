import { ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import Panel from "../common/Panel";

export default function ThreatStatus({ stats }) {
  const critical = stats?.severity_breakdown?.CRITICAL ?? 0;
  const high     = stats?.severity_breakdown?.HIGH ?? 0;
  const total    = stats?.total_alerts ?? 0;

  const level =
    critical > 5 ? "Critical" :
    critical > 0 ? "High" :
    high > 0     ? "Medium" :
    total > 0    ? "Low" : "Normal";

  const cfg = {
    Critical: { color:"#EF4444", dim:"rgba(239,68,68,0.1)", Icon:ShieldX,     desc:"Immediate action required" },
    High:     { color:"#F97316", dim:"rgba(249,115,22,0.1)", Icon:ShieldAlert, desc:"Elevated threat activity" },
    Medium:   { color:"#F59E0B", dim:"rgba(245,158,11,0.1)", Icon:ShieldAlert, desc:"Monitor closely" },
    Low:      { color:"#10B981", dim:"rgba(16,185,129,0.1)", Icon:ShieldCheck, desc:"Low threat level" },
    Normal:   { color:"#10B981", dim:"rgba(16,185,129,0.1)", Icon:ShieldCheck, desc:"All clear" },
  }[level];

  return (
    <Panel title="Threat Level" accent={cfg.color}>
      <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", padding:"1.5rem 0", textAlign:"center" }}>
        <div style={{
          width:72, height:72, borderRadius:"50%",
          background:cfg.dim, border:`2px solid ${cfg.color}40`,
          display:"flex", alignItems:"center", justifyContent:"center",
          marginBottom:"1rem",
        }}>
          <cfg.Icon size={32} color={cfg.color} />
        </div>
        <h2 style={{ fontSize:24, fontWeight:700, color:cfg.color, marginBottom:6 }}>{level}</h2>
        <p style={{ fontSize:12, color:"var(--text-secondary)", marginBottom:"1.5rem" }}>{cfg.desc}</p>

        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"0.625rem", width:"100%" }}>
          {[
            { label:"Total",    value:total,    color:"var(--text-primary)" },
            { label:"Critical", value:critical, color:"#FCA5A5" },
            { label:"High",     value:high,     color:"#FDBA74" },
            { label:"Blocked",  value:stats?.total_blocked_ips??0, color:"#93C5FD" },
          ].map(({ label, value, color }) => (
            <div key={label} style={{
              padding:"0.625rem", borderRadius:"var(--radius-sm)",
              background:"var(--bg-base)", border:"1px solid var(--border)", textAlign:"center",
            }}>
              <p style={{ fontSize:18, fontWeight:700, color }}>{value}</p>
              <p style={{ fontSize:10, color:"var(--text-secondary)", marginTop:2 }}>{label}</p>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}
