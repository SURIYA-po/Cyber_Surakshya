import axios from "axios";

// Central Axios instance. All api/* modules go through this — components
// should never import axios directly (see project conventions in README).
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://localhost:8000",
  headers: {
    "Content-Type": "application/json",
  },
});

export default api;
