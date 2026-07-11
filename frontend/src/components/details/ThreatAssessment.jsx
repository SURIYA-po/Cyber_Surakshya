export default function ThreatAssessment({ alert }) {
  if (!alert) return null;
  const score = alert.threatScore ?? 0;
  const barColor = score>=90?"#EF4444":score>=70?"#F97316":score>=50?"#F59E0B":"#10B981";

  return (
    <div className="card" style={{ padding:"1.25rem" }}>
      <h2 style={{ fontSize:13, fontWeight:600, color:"var(--text-primary)", marginBottom:"1rem", paddingBottom:"0.75rem", borderBottom:"1px solid var(--border)" }}>
        Threat Assessment
      </h2>
      <div style={{ marginBottom:"1.25rem" }}>
        <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
          <span style={{ fontSize:11, color:"var(--text-secondary)" }}>Threat Score</span>
          <span style={{ fontSize:13, fontWeight:700, color:barColor }}>{score.toFixed(1)}/100</span>
        </div>
        <div style={{ height:6, borderRadius:99, background:"var(--bg-base)", overflow:"hidden" }}>
          <div style={{ width:`${score}%`, height:"100%", background:barColor, borderRadius:99, transition:"width 0.8s ease" }} />
        </div>
      </div>
      {[
        { label:"Confidence",    value:`${alert.confidence?.toFixed(1) ?? 0}%` },
        { label:"Risk Level",    value:alert.riskLevel ?? alert.severity },
        { label:"MITRE ATT&CK", value:alert.mitre ?? "—" },
      ].map(({ label, value }) => (
        <div key={label} style={{ display:"flex", justifyContent:"space-between", padding:"0.5rem 0", borderBottom:"1px solid var(--border)" }}>
          <span style={{ fontSize:11, color:"var(--text-secondary)" }}>{label}</span>
          <span style={{ fontSize:12, fontWeight:500, color:"var(--text-primary)" }}>{value}</span>
        </div>
      ))}
    </div>
  );
}
