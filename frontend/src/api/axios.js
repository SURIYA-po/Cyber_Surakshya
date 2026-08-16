import axios from "axios";

// Central Axios instance. All api/* modules go through this — components
// should never import axios directly (see project conventions in README).
//
// The API key comes from the build environment. It used to be the hardcoded
// literal "cyber-surakshya-secret-key", matching the same literal in app.py —
// the credential protecting every endpoint was committed to the repository.
//
// Note this is a Vite build-time variable, so it is embedded in the bundle and
// visible to anyone with the dashboard. That is acceptable only because this
// key authenticates the *dashboard* to a locally-bound backend. It is not a
// user credential and must never be reused as one.
const API_KEY = import.meta.env.VITE_API_KEY;

if (!API_KEY) {
  console.error(
    "VITE_API_KEY is not set. Copy frontend/.env.example to frontend/.env " +
      "and set it to the same value as CYBER_SURAKSHYA_API_KEY in the " +
      "backend .env, or every request will be rejected with 403."
  );
}

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://localhost:8000",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY ?? "",
  },
});

export default api;
