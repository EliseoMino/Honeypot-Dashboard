import type { ReactNode } from "react";

import { fetchSummary } from "../api/client";
import { BreakdownList } from "../components/BreakdownList";
import { EmptyState, ErrorBanner, Loading } from "../components/Feedback";
import { MetricCard } from "../components/MetricCard";
import { useResource } from "../hooks/useResource";
import { formatDateTime } from "../utils/format";

/** RF-04 — resumen de la actividad registrada por el honeypot. */
export function SummaryPage(): ReactNode {
  const summary = useResource((signal) => fetchSummary(signal), []);

  if (summary.error !== null) {
    return <ErrorBanner message={summary.error} onRetry={summary.reload} />;
  }
  if (summary.data === null) {
    return <Loading label="Consultando el resumen" />;
  }

  const data = summary.data;

  return (
    <div className="page">
      <header className="page__header">
        <div>
          <h1>Resumen</h1>
          <p className="page__subtitle">
            Actividad registrada entre {formatDateTime(data.first_event_at)} y{" "}
            {formatDateTime(data.last_event_at)}
          </p>
        </div>
        <button type="button" className="button" onClick={summary.reload}>
          Actualizar
        </button>
      </header>

      <div className="metrics">
        <MetricCard label="Eventos totales" value={data.total_events} />
        <MetricCard label="IPs únicas" value={data.unique_source_ips} />
        <MetricCard label="Sesiones" value={data.unique_sessions} />
        <MetricCard
          label="Intentos de autenticación"
          value={data.auth_attempts}
          hint="Eventos de categoría authentication"
        />
        <MetricCard
          label="Comandos registrados"
          value={data.commands}
          hint="Eventos de categoría command"
        />
        <MetricCard
          label="Alertas generadas"
          value={data.alerts}
          hint="Pendiente de RF-11 y RF-12: siempre 0"
        />
      </div>

      {data.total_events === 0 ? (
        <EmptyState>
          Todavía no hay eventos almacenados. Cuando el honeypot genere actividad aparecerá aquí.
        </EmptyState>
      ) : (
        <div className="panels">
          <BreakdownList title="Tipos de evento más frecuentes" entries={data.top_event_types} />
          <BreakdownList title="Por categoría" entries={data.by_category} />
          <BreakdownList title="Por resultado" entries={data.by_outcome} />
          <BreakdownList title="Por protocolo" entries={data.by_protocol} />
        </div>
      )}

      {summary.loading ? <p className="state state--loading">Actualizando…</p> : null}
    </div>
  );
}
