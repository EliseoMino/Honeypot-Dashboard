import { useMemo, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { fetchEventPage, fetchSummary, MAX_LIMIT } from "../api/client";
import type { NormalizedEvent, Order } from "../api/types";
import { EmptyState, ErrorBanner, Loading } from "../components/Feedback";
import {
  EMPTY_FILTERS,
  EventFilters,
  isFiltered,
  type EventFilterValues,
} from "../components/EventFilters";
import { Pagination } from "../components/Pagination";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatNumber } from "../utils/format";

const DEFAULT_LIMIT = 50;

const FILTER_KEYS = [
  "q",
  "event_type",
  "source_ip",
  "event_category",
  "outcome",
  "session_id",
] as const;

function readFilters(params: URLSearchParams): EventFilterValues {
  return {
    search: params.get("q") ?? "",
    eventType: params.get("event_type") ?? "",
    sourceIp: params.get("source_ip") ?? "",
    category: params.get("event_category") ?? "",
    outcome: params.get("outcome") ?? "",
    sessionId: params.get("session_id") ?? "",
  };
}

function readNumber(params: URLSearchParams, key: string, fallback: number): number {
  const value = Number.parseInt(params.get(key) ?? "", 10);
  return Number.isFinite(value) ? value : fallback;
}

/** RF-06 — consulta de eventos: orden, filtros combinados y paginación. */
export function EventsPage(): ReactNode {
  const [params, setParams] = useSearchParams();

  const filters = useMemo(() => readFilters(params), [params]);
  const order: Order = params.get("order") === "asc" ? "asc" : "desc";
  const limit = Math.min(Math.max(readNumber(params, "limit", DEFAULT_LIMIT), 1), MAX_LIMIT);
  const offset = Math.max(readNumber(params, "offset", 0), 0);

  const queryKey = params.toString();
  const page = useResource(
    (signal) =>
      fetchEventPage(
        {
          eventType: filters.eventType,
          sourceIp: filters.sourceIp,
          search: filters.search,
          category: filters.category,
          outcome: filters.outcome,
          sessionId: filters.sessionId,
          limit,
          offset,
          order,
        },
        signal,
      ),
    [queryKey],
  );

  // Suggestions for the type filter, taken from what the honeypot reported.
  const types = useResource((signal) => fetchSummary(signal), []);
  const knownTypes =
    types.data?.top_event_types
      .map((entry) => entry.key)
      .filter((key): key is string => key !== null) ?? [];

  const changeParams = (mutate: (next: URLSearchParams) => void) => {
    const next = new URLSearchParams(params);
    mutate(next);
    setParams(next);
  };

  const applyFilters = (applied: EventFilterValues) => {
    changeParams((next) => {
      for (const key of FILTER_KEYS) next.delete(key);
      const mapping: Record<keyof EventFilterValues, string> = {
        search: "q",
        eventType: "event_type",
        sourceIp: "source_ip",
        category: "event_category",
        outcome: "outcome",
        sessionId: "session_id",
      };
      for (const field of Object.keys(mapping) as (keyof EventFilterValues)[]) {
        const value = applied[field].trim();
        if (value !== "") next.set(mapping[field], value);
      }
      next.delete("offset");
    });
  };

  const toggleOrder = () => {
    changeParams((next) => {
      if (order === "desc") next.set("order", "asc");
      else next.delete("order");
    });
  };

  const items = page.data?.items ?? [];

  return (
    <div className="page">
      <header className="page__header">
        <div>
          <h1>Eventos</h1>
          <p className="page__subtitle">
            {isFiltered(filters) ? "Resultados filtrados" : "Todos los eventos almacenados"}
          </p>
        </div>
        <button type="button" className="button" onClick={page.reload}>
          Actualizar
        </button>
      </header>

      <EventFilters
        value={filters}
        knownTypes={knownTypes}
        onApply={applyFilters}
        onReset={() => applyFilters(EMPTY_FILTERS)}
      />

      {page.error !== null ? <ErrorBanner message={page.error} onRetry={page.reload} /> : null}

      {page.data === null && page.loading ? <Loading label="Consultando eventos" /> : null}

      {page.data !== null && items.length === 0 ? (
        <EmptyState>
          {isFiltered(filters)
            ? "Ningún evento coincide con los filtros aplicados."
            : "Todavía no hay eventos almacenados."}
        </EmptyState>
      ) : null}

      {items.length > 0 ? (
        <>
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">
                    <button type="button" className="table__sort" onClick={toggleOrder}>
                      Fecha {order === "asc" ? "▲" : "▼"}
                    </button>
                  </th>
                  <th scope="col">Tipo</th>
                  <th scope="col">Categoría</th>
                  <th scope="col">IP de origen</th>
                  <th scope="col">Sesión</th>
                  <th scope="col">Usuario</th>
                  <th scope="col">Resultado</th>
                  <th scope="col">
                    <span className="visually-hidden">Detalle</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((event) => (
                  <EventRow key={event.event_id} event={event} />
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
        <p className="state state--loading">Actualizando… ({formatNumber(items.length)} en pantalla)</p>
      ) : null}
    </div>
  );
}

function EventRow({ event }: { event: NormalizedEvent }): ReactNode {
  return (
    <tr>
      <td className="table__time">{formatDateTime(event.occurred_at)}</td>
      <td>
        <Link className="link" to={`/events/${encodeURIComponent(event.event_id)}`}>
          {event.event_type}
        </Link>
      </td>
      <td>{event.event_category}</td>
      <td className="table__mono">{event.source_ip ?? "—"}</td>
      <td className="table__mono">{event.session_id ?? "—"}</td>
      <td>{event.username ?? "—"}</td>
      <td>
        {event.outcome === null ? (
          "—"
        ) : (
          <span className={`badge badge--${event.outcome}`}>{event.outcome}</span>
        )}
      </td>
      <td>
        <Link
          className="button button--ghost"
          to={`/events/${encodeURIComponent(event.event_id)}`}
          aria-label={`Ver el detalle de ${event.event_type}`}
        >
          Ver
        </Link>
      </td>
    </tr>
  );
}
