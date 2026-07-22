import { useCallback, useEffect, useState } from "react";

/**
 * Generic data-fetching hook used by pages once they're ready to switch
 * from mock constants to live backend data.
 *
 *   const { data, loading, error, refetch } = useApi(getAlerts);
 *
 * `fetcher` should be one of the functions exported from src/api/*.js.
 * Pass `deps` the same way you would to useEffect, to re-run on change
 * (e.g. when an :id route param changes).
 */
export function useApi(fetcher, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const refetch = useCallback(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    fetcher()
      .then((result) => {
        if (!cancelled) setData(result);
      })
      .catch((err) => {
        if (!cancelled) {
          setError(
            err?.response?.data?.detail ||
              err?.message ||
              "Something went wrong while talking to the backend."
          );
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, deps);

  useEffect(() => {
    const cancel = refetch();
    return cancel;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refetch]);

  return { data, loading, error, refetch };
}
