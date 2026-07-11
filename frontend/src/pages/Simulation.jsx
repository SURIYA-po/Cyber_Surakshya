import { useState } from "react";
import { PlayCircle, CheckCircle2, Loader2, ShieldAlert, Zap, Brain, Lock, BarChart2 } from "lucide-react";
import { simulateAttack } from "../api/simulationApi";

const STEPS = [
  { label:"Attack Generated",        icon:ShieldAlert, color:"#EF4444" },
  { label:"Threat Score Calculated", icon:BarChart2,   color:"#F59E0B" },
  { label:"AI Analysis Generated",   icon:Brain,       color:"#8B5CF6" },
  { label:"Response Generated",      icon:Zap,         color:"#F97316" },
  { label:"Source IP Blocked",       icon:Lock,        color:"#3B82F6" },
];

export default function Simulation() {
  const [running, setRunning] = useState(false);
  const [step, setStep] = useState(-1);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleRun() {
    setRunning(true); setError(null); setResult(null); setStep(-1);
    try {
      const apiCall = simulateAttack();
      for (let i = 0; i < STEPS.length; i++) {
        await new Promise((r) => setTimeout(r, 420));
        setStep(i);
      }
      const data = await apiCall;
      setResult(data);
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || "Could not reach the backend.");
    } finally {
      setRunning(false);
    }
  }

  const isDone = !running && result;

  return (
    <div className="page">
      <div style={{ marginBottom:"1.5rem" }}>
        <h1 style={{ fontSize:20, fontWeight:700, color:"var(--text-primary)", marginBottom:4 }}>Attack Simulation</h1>
        <p style={{ fontSize:12, color:"var(--text-secondary)" }}>Trigger a complete simulated security incident end-to-end.</p>
      </div>

      {/* Trigger card */}
      <div className="card" style={{ padding:"1.5rem", marginBottom:"1.25rem" }}>
        <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:"1.5rem", flexWrap:"wrap" }}>
          <div style={{ display:"flex", gap:"1rem", alignItems:"flex-start" }}>
            <div style={{
              width:44, height:44, borderRadius:"var(--radius)",
              background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.25)",
              display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0,
            }}>
              <ShieldAlert size={20} color="#EF4444" />
            </div>
            <div>
              <h2 style={{ fontSize:15, fontWeight:600, color:"var(--text-primary)", marginBottom:4 }}>
                Simulate a Security Incident
              </h2>
              <p style={{ fontSize:12, color:"var(--text-secondary)", maxWidth:440, lineHeight:1.6 }}>
                Generates a random attack, scores it, runs AI analysis, creates a response,
                and blocks the source IP — the complete SOC workflow in one click.
              </p>
            </div>
          </div>
          <button className="btn-primary" onClick={handleRun} disabled={running} style={{ flexShrink:0 }}>
            {running ? <Loader2 size={14} className="animate-spin" /> : <PlayCircle size={14} />}
            {running ? "Running…" : "Generate Attack"}
          </button>
        </div>
      </div>

      <div className={result ? "grid-2" : ""} style={{ gap:"var(--gap)" }}>
        {/* Workflow steps */}
        <div className="card" style={{ padding:"1.25rem" }}>
          <h3 style={{ fontSize:12, fontWeight:600, color:"var(--text-primary)", marginBottom:"1rem", paddingBottom:"0.75rem", borderBottom:"1px solid var(--border)" }}>
            Workflow
          </h3>
          <div style={{ display:"flex", flexDirection:"column", gap:"0.625rem" }}>
            {STEPS.map((s, i) => {
              const done   = i <= step || isDone;
              const active = i === step + 1 && running;
              const StepIcon = s.icon;
              return (
                <div key={s.label} style={{
                  display:"flex", alignItems:"center", gap:"0.75rem",
                  padding:"0.625rem 0.875rem",
                  borderRadius:"var(--radius)",
                  background: done ? `${s.color}0A` : "var(--bg-base)",
                  border:`1px solid ${done ? `${s.color}30` : "var(--border)"}`,
                  transition:"all 0.3s ease",
                }}>
                  <div style={{
                    width:28, height:28, borderRadius:"var(--radius-sm)",
                    background: done ? `${s.color}20` : "var(--bg-card)",
                    border:`1px solid ${done ? `${s.color}40` : "var(--border)"}`,
                    display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0,
                  }}>
                    {active
                      ? <Loader2 size={13} color={s.color} className="animate-spin" />
                      : done
                        ? <CheckCircle2 size={13} color={s.color} />
                        : <StepIcon size={13} color="var(--text-muted)" />
                    }
                  </div>
                  <span style={{ fontSize:12, fontWeight:500, color: done ? "var(--text-primary)" : "var(--text-secondary)" }}>
                    {s.label}
                  </span>
                </div>
              );
            })}
          </div>

          {error && (
            <div style={{ marginTop:"1rem", background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.25)", borderRadius:"var(--radius)", padding:"0.75rem", fontSize:12, color:"#FCA5A5" }}>
              {error}
            </div>
          )}
        </div>

        {/* Live results */}
        {result && (
          <div className="card" style={{ padding:"1.25rem", borderColor:"rgba(16,185,129,0.25)" }}>
            <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:"1rem", paddingBottom:"0.75rem", borderBottom:"1px solid var(--border)" }}>
              <CheckCircle2 size={14} color="#10B981" />
              <h3 style={{ fontSize:12, fontWeight:600, color:"#10B981" }}>Simulation Complete</h3>
            </div>

            <div style={{ display:"flex", flexDirection:"column", gap:"0.625rem" }}>
              {[
                { label:"Attack",     value:`${result.alert?.attack_type}`,                      sub:`from ${result.alert?.source_ip}` },
                { label:"Severity",   value:result.alert?.severity,                              sub:`Alert #${result.alert?.id}` },
                { label:"AI Predict", value:result.analysis?.prediction,                         sub:`${result.analysis?.confidence?.toFixed(1)}% confidence` },
                { label:"Score",      value:`${result.threat_score?.score}/100`,                 sub:`${result.threat_score?.risk} · ${result.threat_score?.priority}` },
                { label:"Response",   value:result.response?.action,                             sub:result.response?.status },
                result.blocked_ip
                  ? { label:"Blocked",  value:result.blocked_ip?.ip, sub:"IP blocked" }
                  : { label:"Blocked",  value:"None", sub:"IP not blocked" },
              ].map(({ label, value, sub }) => (
                <div key={label} style={{
                  display:"flex", alignItems:"center", justifyContent:"space-between",
                  padding:"0.5rem 0.75rem",
                  borderRadius:"var(--radius-sm)",
                  background:"var(--bg-base)",
                  border:"1px solid var(--border)",
                }}>
                  <span style={{ fontSize:10, color:"var(--text-secondary)", fontWeight:600, textTransform:"uppercase", letterSpacing:"0.06em" }}>
                    {label}
                  </span>
                  <div style={{ textAlign:"right" }}>
                    <p style={{ fontSize:12, fontWeight:600, color:"var(--text-primary)" }}>{value}</p>
                    <p style={{ fontSize:10, color:"var(--text-secondary)" }}>{sub}</p>
                  </div>
                </div>
              ))}
            </div>

            <p style={{ fontSize:11, color:"var(--text-secondary)", marginTop:"0.875rem" }}>
              Check the Alerts and Blocked IPs pages for the new records.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
