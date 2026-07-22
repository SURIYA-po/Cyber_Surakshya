import api from "./axios";

export async function getStats() {
  const { data } = await api.get("/stats");
  return data;
}
