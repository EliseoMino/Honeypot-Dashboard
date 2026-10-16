import { useMemo, type ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { fetchSessionTimeline, MAX_LIMIT } from "../api/client";
import { IpCountry } from "../components/IpCountry";
import { ErrorBanner, Loading } from "../components/Feedback";
import { Pagination } from "../components/Pagination";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatNumber } from "../utils/format";

const PAGE_SIZE = 100;

function readOffset(params: URLSearchParams): number {
  const offset = Number.parseInt(params.get("offset") ?? "0", 10);
  return Number.isFinite(offset) ? Math.max(0, offset) : 0;
}

export function SessionDetailPage(): ReactNode {
  const { sessionId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const offset = useMemo(() => readOffset(params), [params]);
  const requestedLimit = Number.parseInt(params.get("limit") ?? String(PAGE_SIZE), 10);
  const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(requestedLimit, MAX_LIMIT)) : PAGE_SIZE;
  const queryKey = `${sessionId}:${offset}:${limit}`;
  const timeline = useResource(
    (signal) => fetchSessionTimeline(sessionId, limit, offset, signal),
    [queryKey],
  );
  if (timeline.error !== null) {
    return <div className="page"><Link className="link" to="/sessions">← Volver a sesiones</Link><ErrorBanner message={timeline.error} onRetry={timeline.reload} /></div>;
  }
  if (timeline.data === null) return <Loading label="Cargando cronología de la sesión" />;
  const { summary, events, alerts } = timeline.data;

  return (
    <div className="page">
      <Link className="link" to="/sessions">← Volver a sesiones</Link>
      <header className="page__header">
        <div>
          <h1 className="mono">Sesión {summary.session_id}</h1>
          <p className="page__subtitle">
            IP {summary.source_ip ?? "desconocida"}
            <IpCountry countryCode={summary.country_code} countryName={summary.country_name} />
            {" · "}{formatNumber(summary.event_count)} eventos · {formatDateTime(summary.first_seen)} → {formatDateTime(summary.last_seen)}
          </p>
        </div>
        <div className="refresh"><Link className="button" to={`/commands?session_id=${encodeURIComponent(sessionId)}`}>Ver comandos</Link><button className="button" type="button" onClick={timeline.reload}>Actualizar</button></div>
      </header>

      {alerts.length > 0 ? (
        <section className="panel">
          <h2 className="panel__title">Alertas relacionadas ({alerts.length})</h2>
          <ul className="evidence-list">
            {alerts.map((alert) => <li key={alert.id}><Link className="link" to={`/alerts/${alert.id}`}>{alert.title}</Link> · {alert.severity} · {alert.status} · {formatDateTime(alert.generated_at)}</li>)}
          </ul>
        </section>
      ) : <p className="page__subtitle">No hay alertas relacionadas con esta sesión.</p>}

      {events.length === 0 ? <p className="state">La sesión no tiene eventos en esta página.</p> : (
        <ol className="session-timeline">
          {events.map((event) => (
            <li className="session-timeline__item" key={event.event_id}>
              <time className="session-timeline__time">{formatDateTime(event.occurred_at)}</time>
              <div className="session-timeline__body">
                <div className="session-timeline__heading">
                  <span className="mono">{event.event_type}</span>
                  {event.outcome ? <span className={`badge badge--${event.outcome === "success" ? "low" : "high"}`}>{event.outcome}</span> : null}
                </div>
                <p className="page__subtitle">
                  {event.source_ip ?? "IP desconocida"}<IpCountry countryCode={event.country_code} countryName={event.country_name} />
                  {event.username ? ` · usuario ${event.username}` : ""}
                  {event.protocol ? ` · ${event.protocol}` : ""}
                </p>
                <Link className="link" to={`/events/${encodeURIComponent(event.event_id)}`}>Abrir evento</Link>
              </div>
            </li>
          ))}
        </ol>
      )}
      <Pagination
        total={timeline.data.total}
        limit={limit}
        offset={offset}
        onOffsetChange={(nextOffset) => {
          const next = new URLSearchParams(params);
          if (nextOffset === 0) next.delete("offset"); else next.set("offset", String(nextOffset));
          setParams(next);
        }}
        onLimitChange={(nextLimit) => {
          const next = new URLSearchParams(params);
          if (nextLimit === PAGE_SIZE) next.delete("limit"); else next.set("limit", String(nextLimit));
          next.delete("offset");
          setParams(next);
        }}
      />
    </div>
  );
}
