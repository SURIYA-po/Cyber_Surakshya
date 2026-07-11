const map = {
  New:           { bg:"rgba(59,130,246,0.1)",  border:"rgba(59,130,246,0.25)",  color:"#93C5FD" },
  Open:          { bg:"rgba(59,130,246,0.1)",  border:"rgba(59,130,246,0.25)",  color:"#93C5FD" },
  Investigating: { bg:"rgba(245,158,11,0.1)",  border:"rgba(245,158,11,0.25)",  color:"#FCD34D" },
  Monitoring:    { bg:"rgba(6,182,212,0.1)",   border:"rgba(6,182,212,0.25)",   color:"#67E8F9" },
  Resolved:      { bg:"rgba(16,185,129,0.1)",  border:"rgba(16,185,129,0.25)",  color:"#6EE7B7" },
  Active:        { bg:"rgba(239,68,68,0.1)",   border:"rgba(239,68,68,0.25)",   color:"#FCA5A5" },
};

export default function StatusBadge({ status }) {
  const s = map[status] ?? { bg:"rgba(100,116,139,0.1)", border:"rgba(100,116,139,0.25)", color:"#94A3B8" };
  return (
    <span style={{
      display:"inline-flex", alignItems:"center",
      padding:"2px 8px", borderRadius:20,
      fontSize:11, fontWeight:500,
      background:s.bg, border:`1px solid ${s.border}`, color:s.color,
    }}>
      {status}
    </span>
  );
}
