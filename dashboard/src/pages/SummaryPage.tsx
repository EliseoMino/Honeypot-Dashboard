import type { ReactNode } from "react";
import { useState } from "react";

import { fetchSummary, fetchTimeSeries } from "../api/client";
import type { TimeBucket } from "../api/types";
import { BreakdownList } from "../components/BreakdownList";
import { EmptyState, ErrorBanner, Loading } from "../components/Feedback";
import { MetricCard } from "../components/MetricCard";
import { RefreshControls } from "../components/RefreshControls";
import { TimeSeriesChart } from "../components/TimeSeriesChart";
import { useAutoRefresh } from "../hooks/useAutoRefresh";
import { useRefreshPreference } from "../hooks/useRefreshPreference";
import { useResource } from "../hooks/useResource";
import { formatDateTime } from "../utils/format";

const BUCKET_OPTIONS: { value: TimeBucket; label: string }[] = [
  { value: "minute", label: "Por minuto" },
  { value: "hour", label: "Por hora" },
  { value: "day", label: "Por día" },
];

/** RF-04 — resumen de la actividad registrada por el honeypot. */
export function SummaryPage(): ReactNode {
  const summary = useResource((signal) => fetchSummary(signal), []);
  const [bucket, setBucket] = useState<TimeBucket>("hour");
  const series = useResource((signal) => fetchTimeSeries(bucket, signal), [bucket]);

  const preference = useRefreshPreference();
  const reloadAll = () => {
    void summary.reload();
    void series.reload();
  };
  useAutoRefresh({
    enabled: preference.enabled,
    intervalMs: preference.intervalMs,
    reload: reloadAll,
    busy: summary.loading || series.loading,
  });

  if (summary.error !== null) {
    return (
      <div className="page">
        <ErrorBanner message={summary.error} onRetry={reloadAll} />
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
          onReload={reloadAll}
          loading={summary.loading || series.loading}
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
        <>
          <div className="chart-controls">
            <div className="filters__field">
              <label htmlFor="summary-bucket">Periodo del gráfico</label>
              <select
                id="summary-bucket"
                value={bucket}
                onChange={(event) => setBucket(event.target.value as TimeBucket)}
              >
                {BUCKET_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {series.error !== null ? (
            <ErrorBanner message={series.error} onRetry={series.reload} />
          ) : series.data === null ? (
            <Loading label="Consultando la actividad" />
          ) : (
            <TimeSeriesChart
              points={series.data.points}
              bucket={series.data.bucket}
              title="Evolución de la actividad"
            />
          )}

          <div className="panels">
            <BreakdownList title="Tipos de evento más frecuentes" entries={data.top_event_types} />
            <BreakdownList title="Por categoría" entries={data.by_category} />
            <BreakdownList title="Por resultado" entries={data.by_outcome} />
            <BreakdownList title="Por protocolo" entries={data.by_protocol} />
          </div>
        </>
      )}

      {summary.loading ? <p className="state state--loading">Actualizando…</p> : null}
    </div>
  );
}
