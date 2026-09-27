import { useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { fetchEvent } from "../api/client";
import { ErrorBanner, Loading } from "../components/Feedback";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatEndpoint } from "../utils/format";

/** RF-07 — detalle completo de un evento y su relación con otros registros. */
export function EventDetailPage(): ReactNode {
  const { eventId = "" } = useParams();
  const [showRaw, setShowRaw] = useState(false);
  const event = useResource((signal) => fetchEvent(eventId, signal), [eventId]);

  if (event.error !== null) {
    return (
      <div className="page">
        <Link className="link" to="/events">
          ← Volver a los eventos
        </Link>
        <ErrorBanner message={event.error} onRetry={event.reload} />
      </div>
    );
  }
  if (event.data === null) {
    return <Loading label="Consultando el evento" />;
  }

  const data = event.data;
  const details = Object.entries(data.details);

  return (
    <div className="page">
      <nav className="breadcrumbs">
        <Link className="link" to="/events">
          ← Volver a los eventos
        </Link>
      </nav>
      <header className="page__header">
        <div>
          <h1>{data.event_type}</h1>
          <p className="page__subtitle">
            {data.event_category}
            {data.outcome === null ? "" : ` · ${data.outcome}`} · {formatDateTime(data.occurred_at)}
          </p>
        </div>
        <button type="button" className="button" onClick={event.reload}>
          Actualizar
        </button>
      </header>

      <div className="panels">
        <section className="panel">
          <h2 className="panel__title">Atributos comunes</h2>
          <dl className="attributes">
            <Attribute label="Fecha del evento">{formatDateTime(data.occurred_at)}</Attribute>
            <Attribute label="Recibido">{formatDateTime(data.received_at)}</Attribute>
            <Attribute label="IP de origen">
              {data.source_ip === null ? (
                "—"
              ) : (
                <Link className="link" to={`/events?source_ip=${encodeURIComponent(data.source_ip)}`}>
                  {data.source_ip}
                </Link>
              )}
            </Attribute>
            <Attribute label="Puerto de origen">{data.source_port ?? "—"}</Attribute>
            <Attribute label="Destino">
              {formatEndpoint(data.destination_ip, data.destination_port)}
            </Attribute>
            <Attribute label="Protocolo">{data.protocol ?? "—"}</Attribute>
            <Attribute label="Sesión">
              {data.session_id === null ? (
                "—"
              ) : (
                <Link className="link" to={`/events?session_id=${encodeURIComponent(data.session_id)}`}>
                  {data.session_id}
                </Link>
              )}
            </Attribute>
            <Attribute label="Usuario">{data.username ?? "—"}</Attribute>
            <Attribute label="Sensor">{data.sensor ?? "—"}</Attribute>
            <Attribute label="Resultado">{data.outcome ?? "—"}</Attribute>
            <Attribute label="event_id">
              <span className="mono">{data.event_id}</span>
            </Attribute>
            <Attribute label="Evento de origen">
              <span className="mono">{data.source_event_id}</span>
            </Attribute>
          </dl>
        </section>

        <section className="panel">
          <h2 className="panel__title">Información específica</h2>
          {details.length === 0 ? (
            <p className="state state--empty">Este evento no tiene atributos específicos.</p>
          ) : (
            <dl className="attributes">
              {details.map(([key, value]) => (
                <Attribute key={key} label={key}>
                  {renderValue(value)}
                </Attribute>
              ))}
            </dl>
          )}
        </section>
      </div>

      <section className="panel">
        <div className="panel__header">
          <h2 className="panel__title">Log original de Cowrie</h2>
          <button
            type="button"
            className="button button--ghost"
            onClick={() => setShowRaw((value) => !value)}
            aria-expanded={showRaw}
          >
            {showRaw ? "Ocultar" : "Mostrar"}
          </button>
        </div>
        {showRaw ? <pre className="code">{JSON.stringify(data.raw, null, 2)}</pre> : null}
      </section>
    </div>
  );
}

function Attribute({ label, children }: { label: string; children: ReactNode }): ReactNode {
  return (
    <div className="attributes__row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function renderValue(value: unknown): ReactNode {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return <pre className="code code--inline">{JSON.stringify(value, null, 2)}</pre>;
}
