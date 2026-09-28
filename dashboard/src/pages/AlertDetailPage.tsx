import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { fetchAlert } from "../api/client";
import { ErrorBanner, Loading } from "../components/Feedback";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatNumber } from "../utils/format";

/** Pull the event ids out of the evidence, whatever shape the rule used. */
function evidenceEventIds(evidence: Record<string, unknown>): string[] {
  const ids = evidence.event_ids;
  if (!Array.isArray(ids)) return [];
  return ids.filter((id): id is string => typeof id === "string");
}

/**
 * RF-13 — the alert an analyst actually investigates.
 *
 * The point of this page is the jump from an alert to the activity behind it,
 * so the evidence ids are rendered as links to the events that produced them.
 */
export function AlertDetailPage(): ReactNode {
  const { alertId = "" } = useParams();
  const alert = useResource((signal) => fetchAlert(Number(alertId), signal), [alertId]);

  if (alert.error !== null) {
    return (
      <div className="page">
        <Link className="link" to="/alerts">
          ← Volver a las alertas
        </Link>
        <ErrorBanner message={alert.error} onRetry={alert.reload} />
      </div>
    );
  }
  if (alert.data === null) {
    return <Loading label="Consultando la alerta" />;
  }

  const data = alert.data;
  const eventIds = evidenceEventIds(data.evidence);
  const evidence = Object.entries(data.evidence).filter(([key]) => key !== "event_ids");

  return (
    <div className="page">
      <nav className="breadcrumbs">
        <Link className="link" to="/alerts">
          ← Volver a las alertas
        </Link>
      </nav>
      <header className="page__header">
        <div>
          <h1>{data.title}</h1>
          <p className="page__subtitle">
            <span className={`badge badge--${data.severity}`}>{data.severity}</span>{" "}
            <span className="mono">{data.rule_id}</span> · {formatNumber(data.event_count)} eventos
          </p>
        </div>
        <button type="button" className="button" onClick={alert.reload}>
          Actualizar
        </button>
      </header>

      <div className="panels">
        <section className="panel">
          <h2 className="panel__title">Alerta</h2>
          <dl className="attributes">
            <div className="attributes__row">
              <dt>Descripción</dt>
              <dd>{data.description}</dd>
            </div>
            <div className="attributes__row">
              <dt>Generada</dt>
              <dd>{formatDateTime(data.generated_at)}</dd>
            </div>
            <div className="attributes__row">
              <dt>Actividad entre</dt>
              <dd>
                {formatDateTime(data.occurred_from)} → {formatDateTime(data.occurred_to)}
              </dd>
            </div>
            <div className="attributes__row">
              <dt>IP de origen</dt>
              <dd>
                {data.source_ip === null ? (
                  "—"
                ) : (
                  <Link
                    className="link"
                    to={`/events?source_ip=${encodeURIComponent(data.source_ip)}`}
                  >
                    {data.source_ip}
                  </Link>
                )}
              </dd>
            </div>
            <div className="attributes__row">
              <dt>Sesión</dt>
              <dd>
                {data.session_id === null ? (
                  "—"
                ) : (
                  <Link
                    className="link"
                    to={`/events?session_id=${encodeURIComponent(data.session_id)}`}
                  >
                    {data.session_id}
                  </Link>
                )}
              </dd>
            </div>
            <div className="attributes__row">
              <dt>Tipo de alerta</dt>
              <dd className="mono">{data.alert_type}</dd>
            </div>
            <div className="attributes__row">
              <dt>Detección</dt>
              <dd className="mono">{data.detection_id}</dd>
            </div>
          </dl>
        </section>

        <section className="panel">
          <h2 className="panel__title">Evidencia</h2>
          {evidence.length === 0 ? (
            <p className="state state--empty">La regla no adjuntó evidencia adicional.</p>
          ) : (
            <dl className="attributes">
              {evidence.map(([key, value]) => (
                <div className="attributes__row" key={key}>
                  <dt>{key}</dt>
                  <dd>
                    {typeof value === "string" || typeof value === "number" ? (
                      String(value)
                    ) : (
                      <pre className="code code--inline">{JSON.stringify(value, null, 2)}</pre>
                    )}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </section>
      </div>

      <section className="panel">
        <div className="panel__header">
          <h2 className="panel__title">Eventos que la dispararon</h2>
          {data.source_ip !== null ? (
            <Link
              className="button button--ghost"
              to={`/events?source_ip=${encodeURIComponent(data.source_ip)}`}
            >
              Ver todos los eventos de la IP
            </Link>
          ) : null}
        </div>
        {eventIds.length === 0 ? (
          <p className="state state--empty">
            La detección no guardó los identificadores de los eventos.
          </p>
        ) : (
          <ul className="evidence-list">
            {eventIds.map((id) => (
              <li key={id}>
                <Link className="link mono" to={`/events/${encodeURIComponent(id)}`}>
                  {id}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
