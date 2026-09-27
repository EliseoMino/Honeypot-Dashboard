import { useMemo, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { fetchCommandPage, MAX_LIMIT } from "../api/client";
import type { CommandRecord } from "../api/types";
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

/** The four filters the commands endpoint accepts. */
const FIELDS = ["sourceIp", "username", "search", "sessionId"] as const;

function readFilters(params: URLSearchParams): AggregateFilterValues {
  return {
    sourceIp: params.get("source_ip") ?? "",
    username: params.get("username") ?? "",
    search: params.get("q") ?? "",
    sessionId: params.get("session_id") ?? "",
  };
}

function readNumber(params: URLSearchParams, key: string, fallback: number): number {
  const value = Number.parseInt(params.get(key) ?? "", 10);
  return Number.isFinite(value) ? value : fallback;
}

/** Outcomes are derived from the event type, so unknown ones stay neutral. */
function outcomeBadge(eventType: string): { label: string; className: string } | null {
  if (eventType.endsWith(".failed")) return { label: "fallida", className: "badge--medium" };
  if (eventType.endsWith(".success")) return { label: "exitosa", className: "badge--low" };
  return null;
}

/**
 * RF-09 — consulta de comandos: what the attackers typed.
 *
 * The backend reads the parsed command and the full line out of the stored
 * details, and falls back to the line when Cowrie reported no parsed command,
 * which is why the column shows both and the line is never blank.
 *
 * A command row links to its event, because the command alone does not say
 * whether the shell was a real one or a simulated one.
 */
export function CommandsPage(): ReactNode {
  const [params, setParams] = useSearchParams();

  const filters = useMemo(() => readFilters(params), [params]);
  const limit = Math.min(Math.max(readNumber(params, "limit", DEFAULT_LIMIT), 1), MAX_LIMIT);
  const offset = Math.max(readNumber(params, "offset", 0), 0);

  const queryKey = params.toString();
  const page = useResource(
    (signal) =>
      fetchCommandPage(
        {
          sourceIp: filters.sourceIp,
          username: filters.username,
          search: filters.search,
          sessionId: filters.sessionId,
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
      for (const key of ["source_ip", "username", "q", "session_id"]) next.delete(key);
      const mapping: Record<string, string> = {
        sourceIp: "source_ip",
        username: "username",
        search: "q",
        sessionId: "session_id",
      };
      for (const [field, key] of Object.entries(mapping)) {
        const value = applied[field as keyof AggregateFilterValues];
        if (value !== "") next.set(key, value);
      }
      next.delete("offset");
    });
  };

  const items = page.data?.items ?? [];

  return (
    <div className="page">
      <header className="page__header">
        <div>
          <h1>Comandos</h1>
          <p className="page__subtitle">
            {isAggregateFiltered(filters) ? "Comandos filtrados" : "Todos los comandos ejecutados"}
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

      {page.data === null && page.loading ? <Loading label="Consultando comandos" /> : null}

      {page.data !== null && items.length === 0 ? (
        <EmptyState>
          {isAggregateFiltered(filters)
            ? "Ningún comando coincide con los filtros aplicados."
            : "Todavía no hay comandos registrados."}
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <>
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Fecha</th>
                  <th scope="col">Comando</th>
                  <th scope="col">Línea completa</th>
                  <th scope="col">Resultado</th>
                  <th scope="col">IP de origen</th>
                  <th scope="col">Sesión</th>
                </tr>
              </thead>
              <tbody>
                {items.map((command) => (
                  <CommandRow key={command.event_id} command={command} />
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

function CommandRow({ command }: { command: CommandRecord }): ReactNode {
  const badge = outcomeBadge(command.event_type);

  return (
    <tr>
      <td className="table__time">{formatDateTime(command.occurred_at)}</td>
      <td className="table__mono">{command.command ?? "—"}</td>
      <td className="table__command">
        <Link className="link" to={`/events/${command.event_id}`}>
          {command.command_line ?? "—"}
        </Link>
      </td>
      <td>{badge === null ? "—" : <span className={`badge ${badge.className}`}>{badge.label}</span>}</td>
      <td className="table__mono">
        {command.source_ip === null ? (
          "—"
        ) : (
          <Link className="link" to={`/sources/${encodeURIComponent(command.source_ip)}`}>
            {command.source_ip}
          </Link>
        )}
      </td>
      <td className="table__mono">
        {command.session_id === null ? (
          "—"
        ) : (
          <Link
            className="link"
            to={`/events?session_id=${encodeURIComponent(command.session_id)}`}
          >
            {command.session_id}
          </Link>
        )}
      </td>
    </tr>
  );
}
