import { useEffect, useRef, useState, useCallback } from "react";

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

/**
 * Subscribes to the backend SSE /feed endpoint.
 * New alerts are prepended to `alerts` in real-time.
 *
 * Usage:
 *   const { alerts, connected } = useLiveFeed();
 */
export function useLiveFeed(maxAlerts = 20) {
  const [alerts, setAlerts] = useState([]);
  const [connected, setConnected] = useState(false);
  const esRef = useRef(null);

  const connect = useCallback(() => {
    if (esRef.current) esRef.current.close();

    const es = new EventSource(`${BASE_URL}/feed`);
    esRef.current = es;

    es.addEventListener("connected", () => setConnected(true));

    es.addEventListener("new_alert", (e) => {
      try {
        const alert = JSON.parse(e.data);
        setAlerts((prev) => [alert, ...prev].slice(0, maxAlerts));
      } catch (_) {}
    });

    es.onerror = () => {
      setConnected(false);
      // auto-reconnect after 3s
      setTimeout(connect, 3000);
    };
  }, [maxAlerts]);

  useEffect(() => {
    connect();
    return () => esRef.current?.close();
  }, [connect]);

  return { alerts, connected };
}
