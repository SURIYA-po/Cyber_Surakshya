import { useState } from "react";
import { MessageSquare, Check } from "lucide-react";
import Panel from "../common/Panel";
import { recordFeedback, VERDICTS } from "../../api/learningApi";

/**
 * Analyst verdict on one incident.
 *
 * This is the platform's only ground truth. Nothing else can tell it whether a
 * detection was right: a confident wrong answer is indistinguishable from a
 * confident right one, so false positives, false negatives and accuracy are
 * only knowable from what an analyst records here.
 *
 * `detectionId` is the alert id — alerts are built from detection records, so
 * the two are the same value.
 */
export default function FeedbackPanel({ detectionId, decisionId, predictedLabel }) {
  const [verdict, setVerdict] = useState(null);
  const [notes, setNotes] = useState("");
  const [actualLabel, setActualLabel] = useState("");
  const [saved, setSaved] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  // A corrected verdict is a new record, so the analyst can always rule again.
  const disagreeing = verdict && verdict !== "CORRECT" && verdict !== "NEEDS_REVIEW";

  async function submit() {
    if (!verdict) return;
    setBusy(true);
    setError(null);
    try {
      await recordFeedback({
        detectionId,
        verdict,
        decisionId,
        notes: notes.trim() || undefined,
        actualLabel: actualLabel.trim() || undefined,
      });
      setSaved(verdict);
      setNotes("");
      setActualLabel("");
      setVerdict(null);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not record feedback.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel
      title="Analyst Verdict"
      accent="var(--green)"
      action={<MessageSquare size={13} color="var(--text-secondary)" />}
    >
      <p style={{ fontSize: 11, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: "0.875rem" }}>
        The platform cannot measure its own accuracy. Your ruling is what makes false
        positives, false negatives and detection accuracy computable
        {predictedLabel ? <> — it classified this as <strong style={{ color: "var(--text-primary)" }}>{predictedLabel}</strong>.</> : "."}
      </p>

      {saved && (
        <div style={{
          display: "flex", alignItems: "center", gap: 8,
          background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.25)",
          borderRadius: "var(--radius)", padding: "0.6rem 0.75rem", marginBottom: "0.875rem",
        }}>
          <Check size={13} color="var(--green)" />
          <span style={{ fontSize: 12, color: "#6EE7B7" }}>
            Recorded as {saved}. Rule again to correct it — feedback is append-only history.
          </span>
        </div>
      )}

      {error && (
        <div style={{
          background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)",
          borderRadius: "var(--radius)", padding: "0.6rem 0.75rem", marginBottom: "0.875rem",
          fontSize: 12, color: "#FCA5A5",
        }}>{error}</div>
      )}

      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: "0.875rem" }}>
        {VERDICTS.map((v) => {
          const active = verdict === v.value;
          return (
            <button
              key={v.value}
              onClick={() => setVerdict(active ? null : v.value)}
              style={{
                padding: "0.4rem 0.75rem", borderRadius: "var(--radius)",
                fontSize: 12, fontWeight: 500,
                color: active ? v.tone : "var(--text-secondary)",
                background: active ? `${v.tone}18` : "transparent",
                border: `1px solid ${active ? `${v.tone}55` : "var(--border-strong)"}`,
                transition: "all .12s",
              }}
            >
              {v.label}
            </button>
          );
        })}
      </div>

      {disagreeing && (
        <input
          className="input-base"
          placeholder="What was it actually? (optional, e.g. BENIGN)"
          value={actualLabel}
          onChange={(e) => setActualLabel(e.target.value)}
          style={{ marginBottom: "0.625rem", fontSize: 12 }}
        />
      )}

      <textarea
        className="input-base"
        placeholder="Notes for the next analyst (optional)"
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        rows={2}
        style={{ marginBottom: "0.875rem", fontSize: 12, resize: "vertical" }}
      />

      <button className="btn-primary" onClick={submit} disabled={!verdict || busy} style={{ width: "100%" }}>
        {busy ? "Recording…" : "Record verdict"}
      </button>

      <p className="mono" style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 10 }}>
        detection {String(detectionId).slice(0, 8)}
        {decisionId ? ` · decision ${String(decisionId).slice(0, 8)}` : ""}
      </p>
    </Panel>
  );
}
