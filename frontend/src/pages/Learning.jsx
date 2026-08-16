import { useCallback, useEffect, useState } from "react";
import {
  Brain, RefreshCw, TrendingUp, AlertTriangle, Lightbulb,
  MessageSquare, HelpCircle, Repeat,
} from "lucide-react";
import Panel from "../components/common/Panel";
import {
  getLearningMetrics, getLearningPatterns,
  getLearningRecommendations, runLearningAnalysis, getFeedback,
} from "../api/learningApi";

const PRIORITY_TONE = {
  CRITICAL: "#EF4444",
  HIGH:     "#F97316",
  MEDIUM:   "#F59E0B",
  LOW:      "#64748B",
};

/** Metrics the platform cannot compute without analyst labels. */
const GROUND_TRUTH = new Set([
  "false_positive_rate", "false_negative_rate", "precision",
  "recall", "detection_accuracy", "decision_accuracy",
]);

function label(name) {
  return name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatValue(metric) {
  if (metric.value == null) return null;
  if (metric.unit === "seconds") {
    return metric.value < 1
      ? `${(metric.value * 1000).toFixed(0)} ms`
      : `${metric.value.toFixed(2)} s`;
  }
  return `${(metric.value * 100).toFixed(1)}%`;
}

/**
 * One metric tile.
 *
 * The load-bearing rule: when `sufficient_data` is false the backend sends
 * `value: null`, and this renders "Not enough data" rather than 0%. Showing a
 * number computed from two labels would be read as fact and acted on — the
 * whole point of the backend's evidence guards is lost if the UI fabricates
 * confidence the data does not support.
 */
function MetricTile({ metric }) {
  const value = formatValue(metric);
  const known = metric.sufficient_data && value != null;
  const needsLabels = GROUND_TRUTH.has(metric.name);

  return (
    <div className="card" style={{ padding: "1rem 1.125rem", opacity: known ? 1 : 0.72 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8, gap: 8 }}>
        <p style={{ fontSize: 11, color: "var(--text-secondary)" }}>{label(metric.name)}</p>
        {!known && <HelpCircle size={12} color="var(--text-muted)" />}
      </div>

      {known ? (
        <p style={{ fontSize: 22, fontWeight: 700, color: "var(--text-primary)", lineHeight: 1.1 }}>
          {value}
        </p>
      ) : (
        <p style={{ fontSize: 13, fontWeight: 600, color: "var(--text-muted)", lineHeight: 1.3 }}>
          Not enough data
        </p>
      )}

      <p style={{ fontSize: 10, color: "var(--text-secondary)", marginTop: 6, lineHeight: 1.5 }}>
        {known
          ? `n = ${metric.sample_size}`
          : needsLabels
            ? `Needs analyst feedback · n = ${metric.sample_size}`
            : metric.detail || `n = ${metric.sample_size}`}
      </p>
    </div>
  );
}

/**
 * Feedback coverage. Sits at the top because no ground-truth metric below it
 * means anything without knowing how much of the history a human has labelled.
 */
function CoverageBanner({ metrics }) {
  const total = metrics?.total_incidents ?? 0;
  const labeled = metrics?.labeled_incidents ?? 0;
  const coverage = metrics?.feedback_coverage ?? 0;
  const pct = coverage * 100;
  const tone = pct >= 30 ? "var(--green)" : pct >= 10 ? "var(--yellow)" : "var(--red)";

  return (
    <div className="card" style={{ padding: "1.125rem 1.25rem", marginBottom: "1.5rem" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10, gap: "1rem", flexWrap: "wrap" }}>
        <div>
          <p style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
            Analyst feedback coverage
          </p>
          <p style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 3, lineHeight: 1.55, maxWidth: 640 }}>
            The platform cannot detect its own mistakes — a confident wrong answer looks
            exactly like a confident right one. Every accuracy figure below rests on
            incidents an analyst has ruled on.
          </p>
        </div>
        <div style={{ textAlign: "right" }}>
          <p style={{ fontSize: 26, fontWeight: 700, color: tone, lineHeight: 1 }}>{pct.toFixed(0)}%</p>
          <p style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 3 }}>
            {labeled} of {total} labelled
          </p>
        </div>
      </div>
      <div style={{ height: 6, borderRadius: 4, background: "var(--bg-input)", overflow: "hidden" }}>
        <div style={{ width: `${Math.max(pct, labeled ? 1.5 : 0)}%`, height: "100%", background: tone, transition: "width .4s" }} />
      </div>
      {pct < 10 && (
        <p style={{ fontSize: 11, color: "var(--yellow)", marginTop: 10, lineHeight: 1.55 }}>
          Below 10% coverage the accuracy metrics stay unavailable by design. Rule on
          closed incidents from the alert detail page to make them computable.
        </p>
      )}
    </div>
  );
}

function PatternRow({ pattern }) {
  return (
    <div style={{ padding: "0.7rem 0", borderBottom: "1px solid var(--border)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: "1rem", alignItems: "flex-start" }}>
        <div style={{ minWidth: 0 }}>
          <p style={{ fontSize: 12, color: "var(--text-primary)", lineHeight: 1.5 }}>{pattern.summary}</p>
          <p className="mono" style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
            {pattern.pattern_type.replace(/_/g, " ").toLowerCase()}
          </p>
        </div>
        <span style={{
          fontSize: 11, fontWeight: 700, color: "var(--accent-bright)",
          flexShrink: 0, whiteSpace: "nowrap",
        }}>
          ×{pattern.occurrences}
        </span>
      </div>
    </div>
  );
}

/**
 * A recommendation. The platform recommends and never applies — retraining a
 * model or loosening a threshold from a bad inference degrades detection
 * invisibly, so there is deliberately no "Apply" button here.
 */
function RecommendationCard({ rec }) {
  const tone = PRIORITY_TONE[rec.priority] || "#64748B";
  return (
    <div className="card" style={{ padding: "1rem 1.125rem", marginBottom: "0.75rem", borderLeft: `2px solid ${tone}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 7, flexWrap: "wrap" }}>
        <span style={{
          padding: "0.15rem 0.5rem", borderRadius: 999, fontSize: 10, fontWeight: 600,
          color: tone, background: `${tone}18`, border: `1px solid ${tone}33`,
        }}>
          {rec.priority}
        </span>
        <strong style={{ fontSize: 12, color: "var(--text-primary)" }}>
          {rec.recommendation_type.replace(/_/g, " ")}
        </strong>
      </div>
      <p style={{ fontSize: 12, color: "var(--text-primary)", lineHeight: 1.55, marginBottom: 6 }}>
        {rec.summary}
      </p>
      <p style={{ fontSize: 11, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 8 }}>
        {rec.rationale}
      </p>
      <div style={{
        background: "var(--bg-input)", border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm)", padding: "0.55rem 0.7rem",
      }}>
        <p style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 3, letterSpacing: "0.05em", textTransform: "uppercase" }}>
          Suggested change — applied by a human, never automatically
        </p>
        <p style={{ fontSize: 11, color: "var(--text-primary)", lineHeight: 1.55 }}>
          {rec.suggested_change}
        </p>
      </div>
    </div>
  );
}

export default function Learning() {
  const [metrics, setMetrics] = useState(null);
  const [patterns, setPatterns] = useState([]);
  const [recommendations, setRecommendations] = useState([]);
  const [feedback, setFeedback] = useState([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [m, p, r, f] = await Promise.all([
        getLearningMetrics(),
        getLearningPatterns(),
        getLearningRecommendations(),
        getFeedback(50).catch(() => []),
      ]);
      setMetrics(m); setPatterns(p); setRecommendations(r); setFeedback(f);
      setError(null);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  async function analyze() {
    setRunning(true);
    try {
      await runLearningAnalysis();
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setRunning(false);
    }
  }

  const list = metrics?.metrics ?? [];
  const timing = list.filter((m) => m.unit === "seconds");
  const ratios = list.filter((m) => m.unit !== "seconds");

  return (
    <div className="page" style={{ maxWidth: "none" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "1.5rem", gap: "1rem", flexWrap: "wrap" }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)", marginBottom: 4 }}>
            Learning
          </h1>
          <p style={{ fontSize: 12, color: "var(--text-secondary)" }}>
            How well the platform has actually been performing — and what to change.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.625rem" }}>
          <button className="btn-ghost" onClick={refresh}>
            <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> Refresh
          </button>
          <button className="btn-primary" onClick={analyze} disabled={running}>
            <Brain size={12} /> {running ? "Analysing…" : "Run Analysis"}
          </button>
        </div>
      </div>

      {error && (
        <div style={{
          background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)",
          borderRadius: "var(--radius)", padding: "0.7rem 0.875rem", marginBottom: "1rem",
          fontSize: 12, color: "#FCA5A5",
        }}>{error}</div>
      )}

      <CoverageBanner metrics={metrics} />

      <p className="section-title" style={{ fontSize: 11, marginBottom: "0.75rem" }}>
        Detection & decision quality
      </p>
      <div className="grid-cards-sm" style={{ marginBottom: "1.5rem" }}>
        {ratios.map((m) => <MetricTile key={m.name} metric={m} />)}
      </div>

      {timing.length > 0 && (
        <>
          <p className="section-title" style={{ fontSize: 11, marginBottom: "0.75rem" }}>
            Response timing
          </p>
          <div className="grid-cards-sm" style={{ marginBottom: "1.5rem" }}>
            {timing.map((m) => <MetricTile key={m.name} metric={m} />)}
          </div>
        </>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "var(--gap)" }} className="lg:grid-cols-2">
        <Panel title={`Recommendations (${recommendations.length})`} accent="var(--yellow)">
          {recommendations.length === 0 ? (
            <p style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              No recommendations yet. Run an analysis once there is incident history.
            </p>
          ) : (
            recommendations.map((r, i) => <RecommendationCard key={i} rec={r} />)
          )}
        </Panel>

        <div style={{ display: "flex", flexDirection: "column", gap: "var(--gap)" }}>
          <Panel title={`Patterns (${patterns.length})`} accent="var(--cyan)">
            {patterns.length === 0 ? (
              <p style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                No recurring patterns above threshold — repeat attackers, repeated
                failures and recurring incidents appear here as history builds.
              </p>
            ) : (
              patterns.map((p, i) => <PatternRow key={i} pattern={p} />)
            )}
          </Panel>

          <Panel title={`Recent Analyst Verdicts (${feedback.length})`} accent="var(--green)">
            {feedback.length === 0 ? (
              <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                No feedback recorded. Open an alert and rule on it — this is the only
                ground truth the platform has, and every accuracy metric depends on it.
              </p>
            ) : (
              feedback.slice(0, 12).map((f) => (
                <div key={f.feedback_id} style={{
                  display: "flex", justifyContent: "space-between", gap: "0.75rem",
                  padding: "0.45rem 0", borderBottom: "1px solid var(--border)",
                }}>
                  <span className="mono" style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                    {String(f.detection_id).slice(0, 8)}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--text-primary)" }}>{f.verdict}</span>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{f.analyst}</span>
                </div>
              ))
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
