import api from "./axios";

export async function simulateAttack() {
  const { data } = await api.post("/simulation/simulate-attack");
  return data;
}

export async function uploadZeek(file) {
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await api.post("/simulation/upload-zeek", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}
