import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { fetchSourcePage, MAX_LIMIT } from "../api/client";
import type { SourceActivity } from "../api/types";
import { EmptyState, ErrorBanner, Loading } from "../components/Feedback";
import { Pagination } from "../components/Pagination";
import { RefreshControls } from "../components/RefreshControls";
import { useAutoRefresh } from "../hooks/useAutoRefresh";
import { useRefreshPreference } from "../hooks/useRefreshPreference";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatNumber } from "../utils/format";

const DEFAULT_LIMIT = 25;

function readNumber(params: URLSearchParams, key: string, fallback: number): number {
  const value = Number.parseInt(params.get(key) ?? "", 10);
  return Number.isFinite(value) ? value : fallback;
}

/**
 * RF-10 — consulta por IP de origen: what each attacker address did.
 *
 * The backend counts the events, the distinct sessions, the authentication
 * attempts, the commands, the transfers and the failures per address and sorts
 * by event count, so the busiest address comes first and the page keeps it.
 *
 * The endpoint takes no address filter: the list is already grouped by address,
 * so filtering it by address would either return one row or none, which is what
 * the detail view is for.
 */
export function SourcesPage(): ReactNode {
  const [params, setParams] = useSearchParams();

  const limit = Math.min(Math.max(readNumber(params, "limit", DEFAULT_LIMIT), 1), MAX_LIMIT);
  const offset = Math.max(readNumber(params, "offset", 0), 0);

  const queryKey = params.toString();
  const page = useResource(
    (signal) => fetchSourcePage({ limit, offset }, signal),
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

  const items = page.data?.items ?? [];
  const totals = items.reduce(
    (sum, item) => ({
      auth: sum.auth + item.auth_attempts,
      commands: sum.commands + item.commands,
      failures: sum.failures + item.failures,
    }),
    { auth: 0, commands: 0, failures: 0 },
  );

  return (
    <div className="page">
      <header className="page__header">
        <div>
          <h1>IPs de origen</h1>
          <p className="page__subtitle">
            Actividad por dirección
            {page.data !== null ? ` · ${formatNumber(page.data.total)} direcciones` : ""}
          </p>
        </div>
        <RefreshControls
          onReload={page.reload}
          loading={page.loading}
          updatedAt={page.updatedAt}
          preference={preference}
        />
      </header>

      {page.error !== null ? <ErrorBanner message={page.error} onRetry={page.reload} /> : null}

      {page.data === null && page.loading ? <Loading label="Consultando direcciones" /> : null}

      {page.data !== null && items.length === 0 ? (
        <EmptyState>Todavía no hay direcciones de origen registradas.</EmptyState>
      ) : null}

      {items.length > 0 ? (
        <>
          <p className="page__note">
            En esta página: {formatNumber(totals.auth)} intentos de autenticación,{" "}
            {formatNumber(totals.commands)} comandos y {formatNumber(totals.failures)} fallos.
          </p>

          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">IP de origen</th>
                  <th scope="col">Eventos</th>
                  <th scope="col">Sesiones</th>
                  <th scope="col">Autenticaciones</th>
                  <th scope="col">Comandos</th>
                  <th scope="col">Transferencias</th>
                  <th scope="col">Fallos</th>
                  <th scope="col">Usuarios</th>
                  <th scope="col">Último evento</th>
                </tr>
              </thead>
              <tbody>
                {items.map((source) => (
                  <SourceRow key={source.source_ip} source={source} />
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

function SourceRow({ source }: { source: SourceActivity }): ReactNode {
  const ip = source.source_ip;

  return (
    <tr>
      <td className="table__mono">
        <Link className="link" to={`/sources/${encodeURIComponent(ip)}`}>
          {ip}
        </Link>
      </td>
      <td>{formatNumber(source.event_count)}</td>
      <td>{formatNumber(source.session_count)}</td>
      <td>{formatNumber(source.auth_attempts)}</td>
      <td>{formatNumber(source.commands)}</td>
      <td>{formatNumber(source.transfers)}</td>
      <td>{formatNumber(source.failures)}</td>
      <td>{source.usernames.length === 0 ? "—" : source.usernames.join(", ")}</td>
      <td className="table__time">{formatDateTime(source.last_seen)}</td>
    </tr>
  );
}
