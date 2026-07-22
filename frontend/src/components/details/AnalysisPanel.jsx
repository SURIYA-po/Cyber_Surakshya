import { BrainCircuit } from "lucide-react";

const DEFAULT_REC = [
  "Block the source IP immediately.",
  "Review web server access logs.",
  "Patch vulnerable application endpoints.",
  "Enable Web Application Firewall rules.",
  "Notify SOC analysts for further investigation.",
];

export default function AnalysisPanel({ analysis }) {
  return (
    <div className="card" style={{ padding:"1.25rem" }}>
      <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:"1rem", paddingBottom:"0.75rem", borderBottom:"1px solid var(--border)" }}>
        <BrainCircuit size={16} color="var(--cyan)" />
        <h2 style={{ fontSize:13, fontWeight:600, color:"var(--text-primary)" }}>
          {analysis?.title ?? "AI Threat Analysis"}
        </h2>
      </div>

      {!analysis ? (
        <p style={{ fontSize:12, color:"var(--text-secondary)" }}>No analysis available for this alert.</p>
      ) : (
        <div className="grid-analysis">
          <div>
            <p className="section-title" style={{ marginBottom:8 }}>Summary</p>
            <div style={{
              background:"var(--bg-base)", borderRadius:"var(--radius)",
              padding:"0.875rem", border:"1px solid var(--border)",
            }}>
              <p style={{ fontSize:12, color:"var(--text-primary)", lineHeight:1.7 }}>{analysis.summary}</p>
            </div>
          </div>
          <div>
            <p className="section-title" style={{ marginBottom:8 }}>Recommended Actions</p>
            <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
              {(analysis.recommendations ?? DEFAULT_REC).map((item, i) => (
                <div key={i} style={{
                  display:"flex", alignItems:"flex-start", gap:8,
                  padding:"0.5rem 0.75rem",
                  background:"var(--bg-base)", borderRadius:"var(--radius-sm)",
                  border:"1px solid var(--border)",
                  fontSize:12, color:"var(--text-primary)",
                }}>
                  <span style={{ color:"var(--green)", flexShrink:0, marginTop:1 }}>✓</span>
                  {item}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
