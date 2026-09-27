import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { fetchSource } from "../api/client";
import { BreakdownList } from "../components/BreakdownList";
import { ErrorBanner, Loading } from "../components/Feedback";
import { MetricCard } from "../components/MetricCard";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatNumber } from "../utils/format";

/**
 * RF-10 — detalle por IP de origen: everything one attacker address did.
 *
 * The counters are the ones the requirement asks for, and the category
 * breakdown says where its events fall, so an analyst can tell a scanner that
 * only connected from one that also transferred files. Every count links to the
 * events behind it, with the same filters the events page understands.
 */
export function SourceDetailPage(): ReactNode {
  const { sourceIp = "" } = useParams();
  const source = useResource((signal) => fetchSource(sourceIp, signal), [sourceIp]);

  if (source.error !== null) {
    return (
      <div className="page">
        <Link className="link" to="/sources">
          ← Volver a las IPs
        </Link>
        <ErrorBanner message={source.error} onRetry={source.reload} />
      </div>
    );
  }
  if (source.data === null) {
    return <Loading label="Consultando la dirección" />;
  }

  const data = source.data;
  const ip = data.source_ip;

  return (
    <div className="page">
      <nav className="breadcrumbs">
        <Link className="link" to="/sources">
          ← Volver a las IPs
        </Link>
      </nav>

      <header className="page__header">
        <div>
          <h1 className="mono">{ip}</h1>
          <p className="page__subtitle">
            {formatNumber(data.session_count)} sesiones · primer evento{" "}
            {formatDateTime(data.first_seen)} · último evento {formatDateTime(data.last_seen)}
          </p>
        </div>
        <button type="button" className="button" onClick={source.reload}>
          Actualizar
        </button>
      </header>

      <div className="metrics">
        <MetricCard label="Eventos" value={data.event_count} />
        <MetricCard label="Sesiones" value={data.session_count} />
        <MetricCard label="Autenticaciones" value={data.auth_attempts} />
        <MetricCard label="Comandos" value={data.commands} />
        <MetricCard label="Transferencias" value={data.transfers} />
        <MetricCard label="Fallos" value={data.failures} />
      </div>

      <div className="panel-grid">
        <BreakdownList title="Eventos por categoría" entries={data.by_category} />

        <section className="panel">
          <h2 className="panel__title">Explorar</h2>
          <ul className="link-list">
            <li>
              <Link className="link" to={`/events?source_ip=${encodeURIComponent(ip)}`}>
                Todos los eventos de {ip}
              </Link>
            </li>
            <li>
              <Link className="link" to={`/commands?source_ip=${encodeURIComponent(ip)}`}>
                Comandos ejecutados desde {ip}
              </Link>
            </li>
            <li>
              <Link className="link" to={`/sessions?source_ip=${encodeURIComponent(ip)}`}>
                Sesiones abiertas desde {ip}
              </Link>
            </li>
            <li>
              <Link className="link" to={`/alerts?source_ip=${encodeURIComponent(ip)}`}>
                Alertas de {ip}
              </Link>
            </li>
          </ul>
        </section>

        <section className="panel">
          <h2 className="panel__title">Usuarios intentados</h2>
          {data.usernames.length === 0 ? (
            <p className="state">No se intentó ningún usuario.</p>
          ) : (
            <ul className="tag-list">
              {data.usernames.map((username) => (
                <li key={username}>
                  <Link
                    className="link"
                    to={`/sessions?source_ip=${encodeURIComponent(ip)}&username=${encodeURIComponent(username)}`}
                  >
                    {username}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
