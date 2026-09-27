import type { ReactNode } from "react";

import { fetchSummary } from "../api/client";
import { BreakdownList } from "../components/BreakdownList";
import { EmptyState, ErrorBanner, Loading } from "../components/Feedback";
import { MetricCard } from "../components/MetricCard";
import { RefreshControls } from "../components/RefreshControls";
import { useAutoRefresh } from "../hooks/useAutoRefresh";
import { useRefreshPreference } from "../hooks/useRefreshPreference";
import { useResource } from "../hooks/useResource";
import { formatDateTime } from "../utils/format";

/** RF-04 — resumen de la actividad registrada por el honeypot. */
export function SummaryPage(): ReactNode {
  const summary = useResource((signal) => fetchSummary(signal), []);
  const preference = useRefreshPreference();
  useAutoRefresh({
    enabled: preference.enabled,
    intervalMs: preference.intervalMs,
    reload: summary.reload,
    busy: summary.loading,
  });

  if (summary.error !== null) {
    return (
      <div className="page">
        <ErrorBanner message={summary.error} onRetry={summary.reload} />
      </div>
    );
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
        <RefreshControls
          onReload={summary.reload}
          loading={summary.loading}
          updatedAt={summary.updatedAt}
          preference={preference}
        />
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
          hint={data.alerts === 0 ? "Ninguna regla ha detectado actividad" : undefined}
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
