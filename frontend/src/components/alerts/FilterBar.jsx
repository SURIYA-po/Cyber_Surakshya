const sel = {
  background:"var(--bg-input)",
  border:"1px solid var(--border-strong)",
  borderRadius:"var(--radius)",
  padding:"0.45rem 0.75rem",
  fontSize:12,
  color:"var(--text-primary)",
  outline:"none",
  cursor:"pointer",
};

export default function FilterBar({ severity, setSeverity, status, setStatus }) {
  return (
    <div style={{ display:"flex", alignItems:"center", gap:"0.625rem", flexWrap:"wrap" }}>
      <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={sel}>
        {["All","Critical","High","Medium","Low"].map((v) => <option key={v}>{v}</option>)}
      </select>
      <select value={status} onChange={(e) => setStatus(e.target.value)} style={sel}>
        {["All","New","Open","Investigating","Resolved"].map((v) => <option key={v}>{v}</option>)}
      </select>
    </div>
  );
}
