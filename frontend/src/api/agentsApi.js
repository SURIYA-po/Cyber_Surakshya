import api from "./axios";

export async function getAgents() {
  const { data } = await api.get("/agents");
  return data;
}

export async function getAgentStatus() {
  const { data } = await api.get("/agents/status");
  return data;
}
