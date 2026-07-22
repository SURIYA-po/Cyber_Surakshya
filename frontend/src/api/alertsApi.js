import api from "./axios";

export async function getAlerts() {
  const { data } = await api.get("/alerts");
  return data;
}

export async function getAlertById(id) {
  const { data } = await api.get(`/alerts/${id}`);
  return data;
}

export async function getAlertDetail(id) {
  const { data } = await api.get(`/alerts/${id}/detail`);
  return data;
}

export async function deleteAlert(id) {
  await api.delete(`/alerts/${id}`);
}
