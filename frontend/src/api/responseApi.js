import api from "./axios";

/**
 * Response layer — what the platform actually did, and what it is waiting
 * for a human to authorise.
 */

/** All response actions, optionally filtered by ResponseStatus. */
export async function getResponseActions(status) {
  const { data } = await api.get("/response/actions", {
    params: status ? { status } : undefined,
  });
  return data;
}

export async function getResponseAction(responseId) {
  const { data } = await api.get(`/response/actions/${responseId}`);
  return data;
}

/**
 * The human-in-the-loop queue: actions the guard or policy deferred to an
 * analyst. An LLM decision engine cannot self-authorise a destructive action,
 * so this is where those land.
 */
export async function getPendingApprovals() {
  const { data } = await api.get("/response/pending-approvals");
  return data;
}

export async function approveAction(decisionId, approvedBy = "analyst", reason) {
  const { data } = await api.post(
    `/response/actions/${decisionId}/approve`,
    null,
    { params: { approved_by: approvedBy, ...(reason ? { reason } : {}) } }
  );
  return data;
}

export async function rejectAction(decisionId, approvedBy = "analyst", reason) {
  const { data } = await api.post(
    `/response/actions/${decisionId}/reject`,
    null,
    { params: { approved_by: approvedBy, ...(reason ? { reason } : {}) } }
  );
  return data;
}

/** The active authorisation policy: trust tiers, protected ranges, blast radius. */
export async function getResponsePolicy() {
  const { data } = await api.get("/response/policy");
  return data;
}
