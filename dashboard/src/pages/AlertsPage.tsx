import { useMemo, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { fetchAlertPage, MAX_LIMIT } from "../api/client";
import type { Alert } from "../api/types";
import { EmptyState, ErrorBanner, Loading } from "../components/Feedback";
import {
  AlertFilters,
  EMPTY_ALERT_FILTERS,
  isAlertFiltered,
  type AlertFilterValues,
} from "../components/AlertFilters";
import { Pagination } from "../components/Pagination";
import { RefreshControls } from "../components/RefreshControls";
import { useAutoRefresh } from "../hooks/useAutoRefresh";
import { useRefreshPreference } from "../hooks/useRefreshPreference";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatNumber } from "../utils/format";

const DEFAULT_LIMIT = 25;

const FILTER_KEYS = ["severity", "alert_type", "rule_id", "source_ip", "session_id"] as const;

function readFilters(params: URLSearchParams): AlertFilterValues {
  return {
    severity: params.get("severity") ?? "",
    alertType: params.get("alert_type") ?? "",
    ruleId: params.get("rule_id") ?? "",
    sourceIp: params.get("source_ip") ?? "",
    sessionId: params.get("session_id") ?? "",
  };
}

function readNumber(params: URLSearchParams, key: string, fallback: number): number {
  const value = Number.parseInt(params.get(key) ?? "", 10);
  return Number.isFinite(value) ? value : fallback;
}

/**
 * RF-13 — consulta de alertas: the list the analyst starts from.
 *
 * The backend already returns the worst and most recent alerts first, so the
 * page keeps that order instead of re-sorting and risking a different one than
 * the API documents. Severity only drives the badge colour.
 */
export function AlertsPage(): ReactNode {
  const [params, setParams] = useSearchParams();

  const filters = useMemo(() => readFilters(params), [params]);
  const limit = Math.min(Math.max(readNumber(params, "limit", DEFAULT_LIMIT), 1), MAX_LIMIT);
  const offset = Math.max(readNumber(params, "offset", 0), 0);

  const queryKey = params.toString();
  const page = useResource(
    (signal) =>
      fetchAlertPage(
        {
          ruleId: filters.ruleId,
          alertType: filters.alertType,
          severity: filters.severity,
          sourceIp: filters.sourceIp,
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

  const applyFilters = (applied: AlertFilterValues) => {
    changeParams((next) => {
      for (const key of FILTER_KEYS) next.delete(key);
      const mapping: Record<keyof AlertFilterValues, string> = {
        severity: "severity",
        alertType: "alert_type",
        ruleId: "rule_id",
        sourceIp: "source_ip",
        sessionId: "session_id",
      };
      for (const field of Object.keys(mapping) as (keyof AlertFilterValues)[]) {
        const value = applied[field].trim();
        if (value !== "") next.set(mapping[field], value);
      }
      next.delete("offset");
    });
  };

  const items = page.data?.items ?? [];
  const criticalCount = items.filter((alert) => alert.severity === "critical").length;

  return (
    <div className="page">
      <header className="page__header">
        <div>
          <h1>Alertas</h1>
          <p className="page__subtitle">
            {isAlertFiltered(filters) ? "Alertas filtradas" : "Todas las alertas generadas"}
            {criticalCount > 0 ? ` · ${criticalCount} crítica en esta página` : ""}
          </p>
        </div>
        <RefreshControls
          onReload={page.reload}
          loading={page.loading}
          updatedAt={page.updatedAt}
          preference={preference}
        />
      </header>

      <AlertFilters
        value={filters}
        onApply={applyFilters}
        onReset={() => applyFilters(EMPTY_ALERT_FILTERS)}
      />

      {page.error !== null ? <ErrorBanner message={page.error} onRetry={page.reload} /> : null}

      {page.data === null && page.loading ? <Loading label="Consultando alertas" /> : null}

      {page.data !== null && items.length === 0 ? (
        <EmptyState>
          {isAlertFiltered(filters)
            ? "Ninguna alerta coincide con los filtros aplicados."
            : "Todavía no hay alertas. Hay que evaluar las reglas de detección."}
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <>
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Generada</th>
                  <th scope="col">Severidad</th>
                  <th scope="col">Alerta</th>
                  <th scope="col">Regla</th>
                  <th scope="col">IP de origen</th>
                  <th scope="col">Eventos</th>
                  <th scope="col">
                    <span className="visually-hidden">Detalle</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((alert) => (
                  <AlertRow key={alert.id} alert={alert} />
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

function AlertRow({ alert }: { alert: Alert }): ReactNode {
  return (
    <tr>
      <td className="table__time">{formatDateTime(alert.generated_at)}</td>
      <td>
        <span className={`badge badge--${alert.severity}`}>{alert.severity}</span>
      </td>
      <td>
        <Link className="link" to={`/alerts/${alert.id}`}>
          {alert.title}
        </Link>
      </td>
      <td className="table__mono">{alert.rule_id}</td>
      <td className="table__mono">{alert.source_ip ?? "—"}</td>
      <td>{formatNumber(alert.event_count)}</td>
      <td>
        <Link
          className="button button--ghost"
          to={`/alerts/${alert.id}`}
          aria-label={`Ver el detalle de ${alert.title}`}
        >
          Ver
        </Link>
      </td>
    </tr>
  );
}
