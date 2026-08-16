const STEPS = ["Attack Detected","Threat Score Calculated","AI Analysis Generated","Response Executed"];

export default function Timeline({ alert }) {
  const items = alert?.timeline?.length
    ? alert.timeline.map((item) => ({ event: item.title, time: item.time || "—", detail: item.detail }))
    : (alert ? STEPS.map((event, i) => ({ event, time: i===0 ? alert.time : "—", detail: "" })) : []);

  return (
    <div className="card" style={{ padding:"1.25rem" }}>
      <h2 style={{ fontSize:13, fontWeight:600, color:"var(--text-primary)", marginBottom:"1rem", paddingBottom:"0.75rem", borderBottom:"1px solid var(--border)" }}>
        Attack Timeline
      </h2>
      {!items.length ? (
        <p style={{ fontSize:12, color:"var(--text-secondary)" }}>No timeline data.</p>
      ) : (
        <div style={{ position:"relative" }}>
          <div style={{ position:"absolute", left:8, top:12, bottom:12, width:1, background:"var(--border-strong)" }} />
          <div style={{ display:"flex", flexDirection:"column", gap:"0.875rem" }}>
            {items.map((item, i) => (
              <div key={i} style={{ display:"flex", gap:"1rem", paddingLeft:"1.375rem", position:"relative" }}>
                <div style={{
                  position:"absolute", left:2, top:3,
                  width:13, height:13, borderRadius:"50%",
                  background:"var(--accent)", border:"2px solid var(--bg-card)",
                  flexShrink:0,
                }} />
                <div style={{ flex:1 }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"baseline", gap:8 }}>
                    <p style={{ fontSize:12, fontWeight:500, color:"var(--text-primary)" }}>{item.event}</p>
                    <span style={{ fontSize:10, color:"var(--text-secondary)", flexShrink:0 }}>{item.time}</span>
                  </div>
                  {item.detail && <p style={{ fontSize:11, color:"var(--text-secondary)", marginTop:3 }}>{item.detail}</p>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
