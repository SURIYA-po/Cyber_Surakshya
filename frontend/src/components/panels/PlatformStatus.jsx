import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Radio, Clock, Brain, ArrowRight } from "lucide-react";
import { getIngestionStatus } from "../../api/ingestionApi";
import { getPendingApprovals } from "../../api/responseApi";
import { getLearningMetrics } from "../../api/learningApi";

/**
 * Cross-subsystem strip for the dashboard: is the platform ingesting, is
 * anything waiting on a human, and can it measure itself yet.
 *
 * Each tile links to the page that can act on it — a dashboard number nobody
 * can do anything about is decoration.
 */
function Tile({ to, icon: Icon, label, value, sub, tone, urgent }) {
  return (
    <Link
      to={to}
      className="card"
      style={{
        padding: "1rem 1.125rem", display: "block",
        borderColor: urgent ? `${tone}55` : "var(--border)",
        background: urgent ? `${tone}0D` : "var(--bg-card)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <p style={{ fontSize: 11, color: "var(--text-secondary)" }}>{label}</p>
        <Icon size={13} color={tone} />
      </div>
      <p style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)", lineHeight: 1.15 }}>
        {value}
      </p>
      <div style={{ display: "flex", alignItems: "center", gap: 4, marginTop: 5 }}>
        <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>{sub}</span>
        <ArrowRight size={10} color="var(--text-muted)" />
      </div>
    </Link>
  );
}

export default function PlatformStatus() {
  const [ingestion, setIngestion] = useState(null);
  const [pending, setPending] = useState([]);
  const [metrics, setMetrics] = useState(null);

  useEffect(() => {
    const load = () => {
      getIngestionStatus().then(setIngestion).catch(() => {});
      getPendingApprovals().then(setPending).catch(() => {});
      getLearningMetrics().then(setMetrics).catch(() => {});
    };
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  const running = ingestion?.running ?? false;
  const backlog = ingestion?.stream?.pending ?? 0;
  const events = ingestion?.worker?.events_processed ?? 0;
  const coverage = (metrics?.feedback_coverage ?? 0) * 100;
  const labeled = metrics?.labeled_incidents ?? 0;
  const total = metrics?.total_incidents ?? 0;

  return (
    <div className="grid-cards-sm" style={{ marginBottom: "1.5rem" }}>
      <Tile
        to="/live"
        icon={Radio}
        label="Live ingestion"
        value={running ? "Capturing" : "Stopped"}
        sub={running ? `${events} events · ${backlog} queued` : "Go live to tap an interface"}
        tone={running ? "#10B981" : "#64748B"}
        urgent={running && backlog > 0}
      />
      <Tile
        to="/response"
        icon={Clock}
        label="Awaiting your approval"
        value={pending.length}
        sub={pending.length ? "Actions blocked pending a human" : "Nothing waiting"}
        tone={pending.length ? "#F59E0B" : "#64748B"}
        urgent={pending.length > 0}
      />
      <Tile
        to="/learning"
        icon={Brain}
        label="Feedback coverage"
        value={`${coverage.toFixed(0)}%`}
        sub={
          coverage < 10
            ? `${labeled}/${total} labelled — accuracy unmeasurable`
            : `${labeled} of ${total} incidents labelled`
        }
        tone={coverage >= 30 ? "#10B981" : coverage >= 10 ? "#F59E0B" : "#EF4444"}
        urgent={coverage < 10 && total > 0}
      />
    </div>
  );
}
