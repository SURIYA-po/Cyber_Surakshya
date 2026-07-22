export default function AlertInfoCard({ alert }) {
  if (!alert) return null;
  const rows = [
    { label:"Alert ID",    value:<span className="mono" style={{ fontSize:12 }}>#{alert.id}</span> },
    { label:"Attack Type", value:alert.attackType },
    { label:"Severity",    value:alert.severity },
    { label:"Status",      value:alert.status },
    { label:"Source IP",   value:<span className="mono" style={{ fontSize:12 }}>{alert.sourceIp}</span> },
    { label:"Destination", value:alert.destination },
    { label:"Detected At", value:alert.time },
  ];
  return (
    <div className="card" style={{ padding:"1.25rem" }}>
      <h2 style={{ fontSize:13, fontWeight:600, color:"var(--text-primary)", marginBottom:"1rem", paddingBottom:"0.75rem", borderBottom:"1px solid var(--border)" }}>
        Alert Information
      </h2>
      <div style={{ display:"flex", flexDirection:"column", gap:"0.625rem" }}>
        {rows.map(({ label, value }) => (
          <div key={label} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", paddingBottom:"0.5rem", borderBottom:"1px solid var(--border)" }}>
            <span style={{ fontSize:11, color:"var(--text-secondary)" }}>{label}</span>
            <span style={{ fontSize:12, fontWeight:500, color:"var(--text-primary)" }}>{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
