import { ArrowLeft, RefreshCw, Shield } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import AlertInfoCard from "../components/details/AlertInfoCard";
import ThreatAssessment from "../components/details/ThreatAssessment";
import AnalysisPanel from "../components/details/AnalysisPanel";
import Timeline from "../components/details/Timeline";
import SourceInfo from "../components/details/SourceInfo";
import FeedbackPanel from "../components/details/FeedbackPanel";
import { useApi } from "../hooks/useApi";
import { getAlertDetail } from "../api/alertsApi";

const SEV_COLOR = { CRITICAL:"#EF4444", HIGH:"#F97316", MEDIUM:"#F59E0B", LOW:"#10B981" };

export default function AlertDetail() {
  const { id } = useParams();
  const { data, loading, error, refetch } = useApi(() => getAlertDetail(id), [id]);

  const payload = data && !data.alert && !data.analysis && !data.response_action ? data : data ?? {};
  const alert = payload.alert ?? payload;
  const analysis = payload.analysis ?? null;
  const responseAction = payload.response_action ?? payload.responseAction ?? null;

  const responseActionLabel = (() => {
    if (!responseAction) return null;
    if (typeof responseAction === "string") return responseAction;
    if (typeof responseAction === "object") {
      const action = responseAction.action_type || responseAction.actionType || responseAction.type || "observe";
      const priority = responseAction.priority || "MEDIUM";
      const approval = responseAction.requires_approval ? "requires approval" : "auto-approved";
      return `${String(action).toUpperCase()} • priority ${String(priority).toUpperCase()} • ${approval}`;
    }
    return String(responseAction);
  })();

  const cap = (s) => s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "";

  const alertShape = alert ? {
    id: String(alert.id),
    attackType: alert.attack_type ?? alert.attackType,
    severity: cap(alert.severity),
    status: cap(alert.status),
    sourceIp: alert.source_ip ?? alert.sourceIp,
    destination: "Internal Network",
    time: alert.created_at ? new Date(alert.created_at).toLocaleString() : alert.time,
    threatScore: analysis?.confidence ?? alert.confidence_score ?? 0,
    confidence: analysis?.confidence ?? alert.confidence_score ?? 0,
    riskLevel: cap(alert.severity),
    mitre: "T1190",
    timeline: alert.timeline ?? [],
  } : null;

  const analysisShape = analysis ? {
    title: "AI Threat Analysis",
    summary: analysis.summary,
    recommendations: [
      "Block the source IP immediately.",
      "Review web server access logs.",
      "Patch vulnerable application endpoints.",
      "Enable Web Application Firewall rules.",
      "Notify SOC analysts for further investigation.",
    ],
  } : null;

  const sevColor = alert ? (SEV_COLOR[alert.severity] ?? "#64748B") : "#64748B";

  return (
    <div className="page">
      {/* Header */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"1.5rem", flexWrap:"wrap", gap:"0.75rem" }}>
        <div style={{ display:"flex", alignItems:"center", gap:"0.75rem" }}>
          <Link to="/alerts" style={{
            display:"inline-flex", alignItems:"center", gap:4,
            fontSize:12, color:"var(--text-secondary)",
            padding:"0.35rem 0.625rem",
            borderRadius:"var(--radius-sm)",
            border:"1px solid var(--border)",
            background:"var(--bg-card)",
          }}>
            <ArrowLeft size={12} />
            Alerts
          </Link>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <Shield size={14} color={sevColor} />
            <h1 style={{ fontSize:16, fontWeight:700, color:"var(--text-primary)" }}>
              Alert <span className="mono" style={{ color:sevColor }}>#{id}</span>
            </h1>
          </div>
        </div>
        <button className="btn-ghost" onClick={refetch}>
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Response action banner */}
      {responseActionLabel && (
        <div style={{
          display:"flex", alignItems:"center", gap:"0.75rem",
          padding:"0.75rem 1rem", marginBottom:"1.25rem",
          borderRadius:"var(--radius)",
          background:"var(--accent-dim)", border:"1px solid var(--border-accent)",
        }}>
          <span style={{ fontSize:11, fontWeight:600, color:"var(--accent-bright)", textTransform:"uppercase", letterSpacing:"0.06em" }}>
            Response Action
          </span>
          <span style={{ fontSize:13, color:"var(--text-primary)", fontWeight:500 }}>{responseActionLabel}</span>
        </div>
      )}

      {error && (
        <div style={{
          background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.25)",
          borderRadius:"var(--radius)", padding:"0.75rem 1rem",
          fontSize:12, color:"#FCA5A5", marginBottom:"1.25rem",
        }}>{error}</div>
      )}

      {loading ? (
        <div className="grid-2">
          {[0,1,2,3].map((i) => <div key={i} className="skeleton" style={{ height:200 }} />)}
        </div>
      ) : alertShape ? (
        <>
          <div className="grid-2" style={{ marginBottom:"var(--gap)" }}>
            <AlertInfoCard alert={alertShape} />
            <ThreatAssessment alert={alertShape} />
          </div>
          <div style={{ marginBottom:"var(--gap)" }}>
            <AnalysisPanel analysis={analysisShape} />
          </div>
          <div className="grid-2" style={{ marginBottom:"var(--gap)" }}>
            <Timeline alert={alertShape} />
            <SourceInfo alert={alertShape} />
          </div>
          {/* Closes the feedback loop: the only ground truth LearningAgent has. */}
          <FeedbackPanel
            detectionId={alert.detection_id ?? alert.id}
            decisionId={responseAction?.decision_id}
            predictedLabel={alertShape.attackType}
          />
        </>
      ) : (
        <p style={{ fontSize:13, color:"var(--text-secondary)" }}>Alert not found.</p>
      )}
    </div>
  );
}
