export default function SourceInfo({ alert }) {
  const rows = alert ? [
    { label:"IP Address",  value:<span className="mono" style={{ fontSize:12 }}>{alert.sourceIp}</span> },
    { label:"Country",     value:"—" },
    { label:"City",        value:"—" },
    { label:"ISP",         value:"—" },
    { label:"Reputation",  value:<span style={{ color:"#FCA5A5", fontWeight:600 }}>Malicious</span> },
  ] : [];

  return (
    <div className="card" style={{ padding:"1.25rem" }}>
      <h2 style={{ fontSize:13, fontWeight:600, color:"var(--text-primary)", marginBottom:"1rem", paddingBottom:"0.75rem", borderBottom:"1px solid var(--border)" }}>
        Source Intelligence
      </h2>
      {!rows.length ? (
        <p style={{ fontSize:12, color:"var(--text-secondary)" }}>No source data.</p>
      ) : (
        <div style={{ display:"flex", flexDirection:"column", gap:"0.5rem" }}>
          {rows.map(({ label, value }) => (
            <div key={label} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"0.5rem 0", borderBottom:"1px solid var(--border)" }}>
              <span style={{ fontSize:11, color:"var(--text-secondary)" }}>{label}</span>
              <span style={{ fontSize:12, fontWeight:500, color:"var(--text-primary)" }}>{value}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
