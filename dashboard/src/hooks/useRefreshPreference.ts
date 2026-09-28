/**
 * RF-15 — the refresh preference, remembered between visits.
 *
 * How often a dashboard refreshes is a property of the person watching it, not
 * of the page, so it is kept in `localStorage` instead of in the URL: a shared
 * link must not carry somebody else's polling interval. A dashboard that is
 * read on demand keeps the automatic refresh off, and that choice has to
 * survive a reload of the page.
 *
 * A missing or unreadable value falls back to the defaults, so a browser with
 * storage disabled still gets a working dashboard.
 */

import { useCallback, useState } from "react";

export const REFRESH_STORAGE_KEY = "honeypot-dashboard.refresh";

/** The periods the dashboard offers, in milliseconds. */
export const REFRESH_INTERVALS = [
  { label: "10 s", value: 10_000 },
  { label: "30 s", value: 30_000 },
  { label: "1 min", value: 60_000 },
  { label: "5 min", value: 300_000 },
] as const;

export const DEFAULT_REFRESH_ENABLED = true;
export const DEFAULT_REFRESH_INTERVAL = 60_000;

export interface RefreshPreference {
  enabled: boolean;
  intervalMs: number;
}

export function readRefreshPreference(): RefreshPreference {
  /** Read the stored preference, or the default when there is none. */

  const fallback: RefreshPreference = {
    enabled: DEFAULT_REFRESH_ENABLED,
    intervalMs: DEFAULT_REFRESH_INTERVAL,
  };

  let stored: string | null = null;
  try {
    stored = window.localStorage.getItem(REFRESH_STORAGE_KEY);
  } catch {
    return fallback;
  }
  if (stored === null) return fallback;

  try {
    const parsed: unknown = JSON.parse(stored);
    if (typeof parsed !== "object" || parsed === null) return fallback;
    const { enabled, intervalMs } = parsed as Record<string, unknown>;
    return {
      enabled: typeof enabled === "boolean" ? enabled : fallback.enabled,
      intervalMs: isOffered(intervalMs) ? intervalMs : fallback.intervalMs,
    };
  } catch {
    return fallback;
  }
}

function isOffered(value: unknown): value is number {
  return REFRESH_INTERVALS.some((option) => option.value === value);
}

export interface RefreshControlsState extends RefreshPreference {
  setEnabled: (enabled: boolean) => void;
  setIntervalMs: (intervalMs: number) => void;
}

export function useRefreshPreference(): RefreshControlsState {
  const [preference, setPreference] = useState<RefreshPreference>(readRefreshPreference);

  const store = useCallback((next: RefreshPreference) => {
    setPreference(next);
    try {
      window.localStorage.setItem(REFRESH_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // A browser without storage still refreshes, it just forgets the choice.
    }
  }, []);

  return {
    ...preference,
    setEnabled: (enabled: boolean) => store({ ...preference, enabled }),
    setIntervalMs: (intervalMs: number) => store({ ...preference, intervalMs }),
  };
}
