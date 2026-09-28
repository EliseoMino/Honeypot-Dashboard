/**
 * RF-15 — the controls that decide how fresh the data on screen is.
 *
 * Manual refresh and automatic refresh live together, because they are two ways
 * of doing the same thing: the button reloads now, the switch reloads every so
 * often. The state line says when the data on screen was loaded, which is what
 * tells an operator whether a number is old, and it says so while a request is
 * in flight, so a number is never quietly replaced under the cursor.
 *
 * The preference is owned by the page, not by this component, because the page
 * is what schedules the periodic refresh with it.
 */

import type { ReactNode } from "react";

import { REFRESH_INTERVALS, type RefreshControlsState } from "../hooks/useRefreshPreference";
import { formatClock } from "../utils/format";

export interface RefreshControlsProps {
  /** Reload the data now. */
  onReload: () => void;
  /** Whether a request is in flight. */
  loading: boolean;
  /** When the data on screen was loaded, or null when there is none yet. */
  updatedAt: number | null;
  /** Whether the periodic refresh is on, and every period offered. */
  preference: RefreshControlsState;
}

export function RefreshControls({
  onReload,
  loading,
  updatedAt,
  preference,
}: RefreshControlsProps): ReactNode {
  return (
    <div className="refresh">
      <button type="button" className="button" onClick={onReload} disabled={loading}>
        Actualizar
      </button>

      <label className="refresh__toggle">
        <input
          type="checkbox"
          checked={preference.enabled}
          onChange={(event) => preference.setEnabled(event.target.checked)}
        />
        Actualización automática
      </label>

      <label className="refresh__interval">
        <span className="visually-hidden">Intervalo de actualización automática</span>
        <select
          value={preference.intervalMs}
          disabled={!preference.enabled}
          onChange={(event) => preference.setIntervalMs(Number(event.target.value))}
        >
          {REFRESH_INTERVALS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>

      <p className="refresh__state">
        {loading
          ? "Actualizando…"
          : updatedAt === null
            ? "Sin datos cargados"
            : `Última actualización: ${formatClock(updatedAt)}`}
      </p>
    </div>
  );
}
