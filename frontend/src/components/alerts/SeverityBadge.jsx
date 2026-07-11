const map = {
  Critical: { bg:"rgba(239,68,68,0.1)",  border:"rgba(239,68,68,0.25)",  color:"#FCA5A5", dot:"#EF4444" },
  High:     { bg:"rgba(249,115,22,0.1)", border:"rgba(249,115,22,0.25)", color:"#FDBA74", dot:"#F97316" },
  Medium:   { bg:"rgba(245,158,11,0.1)", border:"rgba(245,158,11,0.25)", color:"#FCD34D", dot:"#F59E0B" },
  Low:      { bg:"rgba(16,185,129,0.1)", border:"rgba(16,185,129,0.25)", color:"#6EE7B7", dot:"#10B981" },
};

export default function SeverityBadge({ severity }) {
  const s = map[severity] ?? map.Low;
  return (
    <span style={{
      display:"inline-flex", alignItems:"center", gap:5,
      padding:"2px 8px", borderRadius:20,
      fontSize:11, fontWeight:500,
      background:s.bg, border:`1px solid ${s.border}`, color:s.color,
    }}>
      <span style={{ width:5, height:5, borderRadius:"50%", background:s.dot, flexShrink:0 }} />
      {severity}
    </span>
  );
}
