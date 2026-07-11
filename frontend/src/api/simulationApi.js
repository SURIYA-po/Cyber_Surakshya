import api from "./axios";

export async function simulateAttack() {
  const { data } = await api.post("/simulation/simulate-attack");
  return data;
}
