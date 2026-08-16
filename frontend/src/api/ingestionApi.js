import api from "./axios";

/**
 * Live network ingestion — the "Go Live" control plane.
 *
 * Every route is authenticated: starting a packet capture is the most
 * privileged operation the platform exposes.
 *
 * Two modes. `capture` taps this host's interface. `remote` taps nothing and
 * instead opens POST /ingestion/pcap so sensors elsewhere can submit closed
 * pcaps, which join the pipeline exactly where a locally captured file would.
 */

/** Sentinel for the interface picker. Not an interface — a mode. */
export const REMOTE_OPTION = "__remote__";

/** Where a remote sensor should point its uploads. */
export function getApiBaseUrl() {
  return api.defaults.baseURL || window.location.origin;
}

/**
 * Can the platform go live, and if not, exactly what is missing.
 * `mode` matters: remote mode needs no dumpcap and no interface, so a host
 * without capture privileges must not be told it cannot ingest anything.
 */
export async function getPreflight(mode) {
  const { data } = await api.get("/ingestion/preflight", {
    params: mode ? { mode } : undefined,
  });
  return data;
}

/** Capturable network interfaces, for the picker. */
export async function getInterfaces() {
  const { data } = await api.get("/ingestion/interfaces");
  return data;
}

/** Capture, stream, worker and pipeline counters. Never contains secrets. */
export async function getIngestionStatus() {
  const { data } = await api.get("/ingestion/status");
  return data;
}

/**
 * Begin ingestion.
 * Backend answers 409 when already running and 422 when a dependency is
 * missing — the caller should surface those differently.
 */
export async function startIngestion(iface, mode) {
  const params = {};
  if (iface) params.interface = iface;
  if (mode) params.mode = mode;
  const { data } = await api.post("/ingestion/start", null, {
    params: Object.keys(params).length ? params : undefined,
  });
  return data;
}

/** Stop capture and worker. Idempotent. */
export async function stopIngestion() {
  const { data } = await api.post("/ingestion/stop");
  return data;
}

/**
 * Submit a pcap the same way a remote sensor would.
 *
 * The response is the *result*, not an ack: the backend extracts flows before
 * replying, so `flows_published` is what this file actually contributed to the
 * pipeline. Expect 409 when ingestion is not running in remote mode, 413 when
 * the file is over the size ceiling, and 415 when it is not a capture.
 */
export async function uploadPcap(file, onProgress) {
  const body = new FormData();
  body.append("file", file);

  // No Content-Type override needed: axios clears the instance's
  // application/json default for FormData so the browser can set
  // multipart/form-data with its own boundary.
  const { data } = await api.post("/ingestion/pcap", body, {
    // Flow extraction runs before the response, so a large pcap legitimately
    // takes a while. A timeout here would abort work already underway on the
    // server, and the sender would never learn what its file produced.
    timeout: 0,
    onUploadProgress: (event) => {
      if (!onProgress || !event.total) return;
      onProgress(Math.round((event.loaded / event.total) * 100));
    },
  });
  return data;
}
