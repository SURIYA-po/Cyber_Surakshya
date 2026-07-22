import api from "./axios";

export async function getAnalyses() {
  const { data } = await api.get("/analyses");
  return data;
}

export async function getAnalysisById(id) {
  const { data } = await api.get(`/analyses/${id}`);
  return data;
}
