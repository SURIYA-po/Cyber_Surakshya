import api from "./axios";

/**
 * Learning layer — how well the platform has actually been doing.
 *
 * Accuracy metrics depend entirely on analyst feedback: the platform cannot
 * detect its own false positives by introspection, so `recordFeedback` is the
 * highest-value input the whole system takes.
 */

/** Metrics only, each carrying its own evidence base. */
export async function getLearningMetrics() {
  const { data } = await api.get("/learning/metrics");
  return data;
}

/** Recurring structures: repeat attackers, failures, attack paths. */
export async function getLearningPatterns() {
  const { data } = await api.get("/learning/patterns");
  return data;
}

/** Ranked advisory proposals. Nothing here is ever applied automatically. */
export async function getLearningRecommendations() {
  const { data } = await api.get("/learning/recommendations");
  return data;
}

/** Run a full learning cycle and persist the report. */
export async function runLearningAnalysis() {
  const { data } = await api.post("/learning/analyze");
  return data;
}

/** The most recent persisted report, without recomputing. */
export async function getLatestReport() {
  const { data } = await api.get("/learning/report");
  return data;
}

export async function getFeedback(limit = 100) {
  const { data } = await api.get("/learning/feedback", { params: { limit } });
  return data;
}

/**
 * Record an analyst verdict — the platform's only ground truth.
 * verdict: CORRECT | INCORRECT | FALSE_POSITIVE | NEEDS_REVIEW | ESCALATE
 */
export async function recordFeedback({
  detectionId,
  verdict,
  analyst = "analyst",
  decisionId,
  notes,
  actualLabel,
}) {
  const { data } = await api.post("/learning/feedback", null, {
    params: {
      detection_id: detectionId,
      verdict,
      analyst,
      ...(decisionId ? { decision_id: decisionId } : {}),
      ...(notes ? { notes } : {}),
      ...(actualLabel ? { actual_label: actualLabel } : {}),
    },
  });
  return data;
}

export const VERDICTS = [
  { value: "CORRECT",        label: "Correct",        tone: "#10B981" },
  { value: "FALSE_POSITIVE", label: "False positive", tone: "#F59E0B" },
  { value: "INCORRECT",      label: "Incorrect",      tone: "#EF4444" },
  { value: "ESCALATE",       label: "Escalate",       tone: "#F97316" },
  { value: "NEEDS_REVIEW",   label: "Needs review",   tone: "#64748B" },
];
