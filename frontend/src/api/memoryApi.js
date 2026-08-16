import api from "./axios";

export async function getMemoryInsights() {
  const { data } = await api.get("/debug/memory");
  return data;
}
