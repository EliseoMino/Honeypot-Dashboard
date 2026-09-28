/**
 * A minimal resource hook: load, reload, cancel in flight, keep the last value.
 *
 * The dashboard has three read endpoints, so a full data library would be more
 * machinery than the requirement asks for.
 */

import { useCallback, useEffect, useRef, useState, type DependencyList } from "react";

import { ApiError } from "../api/client";

export interface Resource<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  /** When the value on screen was loaded, so the UI can say so (RF-15). */
  updatedAt: number | null;
  reload: () => void;
}

export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: DependencyList,
): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [nonce, setNonce] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);

    loadRef
      .current(controller.signal)
      .then((value) => {
        if (controller.signal.aborted) return;
        setData(value);
        setUpdatedAt(Date.now());
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return;
        setData(null);
        setError(cause instanceof ApiError ? cause.message : String(cause));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
    // The caller lists everything the request depends on.
  }, [...deps, nonce]);

  const reload = useCallback(() => setNonce((value) => value + 1), []);

  return { data, error, loading, updatedAt, reload };
}
