/**
 * RF-15 — periodic refresh of the data the dashboard shows.
 *
 * A monitoring dashboard is left open on a screen, so the data it shows has to
 * update by itself. The refresh is opt in and periodic, which is what the
 * requirement asks for as a first version:
 *
 * - A timer reloads the resource every `intervalMs` while it is enabled.
 * - A request that is still in flight is never doubled: the tick is skipped, so
 *   a slow backend cannot pile requests up.
 * - The tab regaining focus reloads once, because the data of a tab that was in
 *   the background is the data an operator most likely wants to see again.
 * - The interval keeps running while the page is hidden, since a dashboard on a
 *   second monitor is often in another tab, and the browser throttles its
 *   timers anyway.
 *
 * Turning the timer off stops it completely: nothing is scheduled and the
 * visibility listener is removed, so a dashboard that is only read on demand
 * never talks to the backend on its own.
 */

import { useEffect, useRef } from "react";

export interface AutoRefreshOptions {
  /** Whether the periodic refresh is on. */
  enabled: boolean;
  /** Milliseconds between two refreshes. */
  intervalMs: number;
  /** Reload the resource. */
  reload: () => void;
  /** Whether a request is in flight, so a tick is not doubled. */
  busy: boolean;
  /** Reload when the tab becomes visible again. Defaults to true. */
  refreshOnFocus?: boolean;
}

export function useAutoRefresh({
  enabled,
  intervalMs,
  reload,
  busy,
  refreshOnFocus = true,
}: AutoRefreshOptions): void {
  // The callbacks change on every render; the refs keep the effect from
  // rescheduling the timer just because a re-render happened.
  const reloadRef = useRef(reload);
  const busyRef = useRef(busy);
  reloadRef.current = reload;
  busyRef.current = busy;

  useEffect(() => {
    if (!enabled) return;

    const tick = () => {
      if (busyRef.current) return;
      reloadRef.current();
    };

    const timer = setInterval(tick, intervalMs);

    const onVisibilityChange = () => {
      if (document.visibilityState === "visible" && refreshOnFocus) tick();
    };
    document.addEventListener("visibilitychange", onVisibilityChange);

    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [enabled, intervalMs, refreshOnFocus]);
}
