import { useMemo, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { fetchSessionPage, MAX_LIMIT } from "../api/client";
import type { SessionSummary } from "../api/types";
import {
  AggregateFilters,
  EMPTY_AGGREGATE_FILTERS,
  isAggregateFiltered,
  type AggregateFilterValues,
} from "../components/AggregateFilters";
import { EmptyState, ErrorBanner, Loading } from "../components/Feedback";
import { Pagination } from "../components/Pagination";
import { RefreshControls } from "../components/RefreshControls";
import { useAutoRefresh } from "../hooks/useAutoRefresh";
import { useRefreshPreference } from "../hooks/useRefreshPreference";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatNumber } from "../utils/format";

const DEFAULT_LIMIT = 25;

/** Only the two filters the sessions endpoint accepts. */
const FIELDS = ["sourceIp", "username"] as const;

function readFilters(params: URLSearchParams): AggregateFilterValues {
  return {
    sourceIp: params.get("source_ip") ?? "",
    username: params.get("username") ?? "",
    search: "",
    sessionId: "",
  };
}

function readNumber(params: URLSearchParams, key: string, fallback: number): number {
  const value = Number.parseInt(params.get(key) ?? "", 10);
  return Number.isFinite(value) ? value : fallback;
}

/** A duration in the largest unit that still reads as a whole number. */
function formatDuration(milliseconds: number | null): string {
  if (milliseconds === null) return "—";
  if (milliseconds < 1000) return `${formatNumber(milliseconds)} ms`;
  const seconds = milliseconds / 1000;
  if (seconds < 60) return `${formatNumber(Math.round(seconds * 10) / 10)} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ${Math.round(seconds % 60)} s`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

/**
 * RF-08 — consulta de sesiones: the sessions the honeypot recorded.
 *
 * The backend groups the events by session id and returns them by last activity,
 * so the page keeps that order. The duration is derived from the first and last
 * event of the session, which is why a session is only as long as the honeypot
 * saw it and not necessarily as long as the attacker stayed connected.
 */
export function SessionsPage(): ReactNode {
  const [params, setParams] = useSearchParams();

  const filters = useMemo(() => readFilters(params), [params]);
  const limit = Math.min(Math.max(readNumber(params, "limit", DEFAULT_LIMIT), 1), MAX_LIMIT);
  const offset = Math.max(readNumber(params, "offset", 0), 0);

  const queryKey = params.toString();
  const page = useResource(
    (signal) =>
      fetchSessionPage(
        {
          sourceIp: filters.sourceIp,
          username: filters.username,
          limit,
          offset,
        },
        signal,
      ),
    [queryKey],
  );

  const preference = useRefreshPreference();
  useAutoRefresh({
    enabled: preference.enabled,
    intervalMs: preference.intervalMs,
    reload: page.reload,
    busy: page.loading,
  });

  const changeParams = (mutate: (next: URLSearchParams) => void) => {
    const next = new URLSearchParams(params);
    mutate(next);
    setParams(next);
  };

  const applyFilters = (applied: AggregateFilterValues) => {
    changeParams((next) => {
      next.delete("source_ip");
      next.delete("username");
      if (applied.sourceIp !== "") next.set("source_ip", applied.sourceIp);
      if (applied.username !== "") next.set("username", applied.username);
      next.delete("offset");
    });
  };

  const items = page.data?.items ?? [];

  return (
    <div className="page">
      <header className="page__header">
        <div>
          <h1>Sesiones</h1>
          <p className="page__subtitle">
            {isAggregateFiltered(filters) ? "Sesiones filtradas" : "Todas las sesiones registradas"}
            {page.data !== null ? ` · ${formatNumber(page.data.total)} en total` : ""}
          </p>
        </div>
        <RefreshControls
          onReload={page.reload}
          loading={page.loading}
          updatedAt={page.updatedAt}
          preference={preference}
        />
      </header>

      <AggregateFilters
        value={filters}
        fields={FIELDS}
        onApply={applyFilters}
        onReset={() => applyFilters(EMPTY_AGGREGATE_FILTERS)}
      />

      {page.error !== null ? <ErrorBanner message={page.error} onRetry={page.reload} /> : null}

      {page.data === null && page.loading ? <Loading label="Consultando sesiones" /> : null}

      {page.data !== null && items.length === 0 ? (
        <EmptyState>
          {isAggregateFiltered(filters)
            ? "Ninguna sesión coincide con los filtros aplicados."
            : "Todavía no hay sesiones. Hay que esperar tráfico contra el honeypot."}
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <>
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Sesión</th>
                  <th scope="col">IP de origen</th>
                  <th scope="col">Inicio</th>
                  <th scope="col">Último evento</th>
                  <th scope="col">Duración</th>
                  <th scope="col">Eventos</th>
                  <th scope="col">Comandos</th>
                  <th scope="col">Usuarios</th>
                  <th scope="col">Autenticó</th>
                </tr>
              </thead>
              <tbody>
                {items.map((session) => (
                  <SessionRow key={session.session_id} session={session} />
                ))}
              </tbody>
            </table>
          </div>

          <Pagination
            total={page.data?.total ?? 0}
            limit={limit}
            offset={offset}
            onOffsetChange={(value) =>
              changeParams((next) => {
                if (value === 0) next.delete("offset");
                else next.set("offset", String(value));
              })
            }
            onLimitChange={(value) =>
              changeParams((next) => {
                next.set("limit", String(value));
                next.delete("offset");
              })
            }
          />
        </>
      ) : null}

      {page.loading && page.data !== null ? (
        <p className="state state--loading">
          Actualizando… ({formatNumber(items.length)} en pantalla)
        </p>
      ) : null}
    </div>
  );
}

function SessionRow({ session }: { session: SessionSummary }): ReactNode {
  const eventQuery = `session_id=${encodeURIComponent(session.session_id)}`;

  return (
    <tr>
      <td className="table__mono">
        <Link className="link" to={`/events?${eventQuery}`}>
          {session.session_id}
        </Link>
      </td>
      <td className="table__mono">
        {session.source_ip === null ? (
          "—"
        ) : (
          <Link className="link" to={`/sources/${encodeURIComponent(session.source_ip)}`}>
            {session.source_ip}
          </Link>
        )}
      </td>
      <td className="table__time">{formatDateTime(session.first_seen)}</td>
      <td className="table__time">{formatDateTime(session.last_seen)}</td>
      <td>{formatDuration(session.duration_ms)}</td>
      <td>{formatNumber(session.event_count)}</td>
      <td>
        {session.command_count === 0 ? (
          "—"
        ) : (
          <Link className="link" to={`/commands?${eventQuery}`}>
            {formatNumber(session.command_count)}
          </Link>
        )}
      </td>
      <td>
        {session.usernames.length === 0 ? (
          "—"
        ) : (
          session.usernames.join(", ")
        )}
      </td>
      <td>
        {session.has_success ? (
          <span className="badge badge--low">con éxito</span>
        ) : session.has_authentication ? (
          <span className="badge badge--medium">fallida</span>
        ) : (
          "—"
        )}
      </td>
    </tr>
  );
}
