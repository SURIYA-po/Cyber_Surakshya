import api from "./axios";

export async function getBlockedIps() {
  const { data } = await api.get("/blocked-ips");
  return data;
}

export async function deleteBlockedIp(id) {
  await api.delete(`/blocked-ips/${id}`);
}
