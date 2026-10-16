import type { ReactNode } from "react";
import { useState } from "react";
import { Link } from "react-router-dom";

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
  const hasActivity = data.total_events > 0;

  return (
    <div className="page summary-page">
      <header className="page__header summary-header">
        <div className="summary-header__copy">
          <p className="summary-eyebrow">CENTRO DE OPERACIONES</p>
          <h1>Resumen de actividad</h1>
          <p className="page__subtitle">
            {hasActivity
              ? `Datos desde ${formatDateTime(data.first_event_at)} hasta ${formatDateTime(data.last_event_at)}`
              : "Todavía no se recibieron eventos de Cowrie."}
          </p>
        </div>
        <RefreshControls
          onReload={reloadAll}
          loading={summary.loading || series.loading}
          updatedAt={summary.updatedAt}
          preference={preference}
        />
      </header>

      <section className="summary-section" aria-labelledby="summary-metrics-title">
        <div className="summary-section__heading">
          <div>
            <p className="summary-eyebrow">VISTA GENERAL</p>
            <h2 id="summary-metrics-title">Actividad registrada</h2>
          </div>
          <span className="summary-period">Acumulado del periodo mostrado</span>
        </div>
        <div className="metrics summary-metrics">
          <MetricCard label="Eventos totales" value={data.total_events} to="/events" />
          <MetricCard label="IPs únicas" value={data.unique_source_ips} to="/sources" />
          <MetricCard label="Sesiones" value={data.unique_sessions} to="/sessions" />
          <MetricCard
            label="Intentos de autenticación"
            value={data.auth_attempts}
            hint="Abrir eventos de autenticación"
            to="/events?event_category=authentication"
          />
          <MetricCard
            label="Comandos registrados"
            value={data.commands}
            hint="Abrir explorador de comandos"
            to="/commands"
          />
          <MetricCard
            label="Alertas generadas"
            value={data.alerts}
            hint={data.alerts === 0 ? "Ninguna regla ha detectado actividad" : "Revisar alertas"}
            to="/alerts"
          />
        </div>
      </section>

      {!hasActivity ? (
        <EmptyState>
          La ingesta está lista para recibir actividad. Cuando Cowrie genere eventos, vas a poder revisar aquí las tendencias y los indicadores.
        </EmptyState>
      ) : (
        <>
          <section className="summary-section" aria-labelledby="summary-trend-title">
            <div className="summary-section__heading summary-section__heading--chart">
              <div>
                <p className="summary-eyebrow">TENDENCIA</p>
                <h2 id="summary-trend-title">Evolución de la actividad</h2>
                <p className="page__subtitle">Autenticaciones y comandos a lo largo del tiempo.</p>
              </div>
              <div className="filters__field summary-bucket">
                <label htmlFor="summary-bucket">Intervalo</label>
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
                title="Eventos por intervalo"
              />
            )}
          </section>

          <section className="summary-section" aria-labelledby="summary-breakdown-title">
            <div className="summary-section__heading">
              <div>
                <p className="summary-eyebrow">DESGLOSE</p>
                <h2 id="summary-breakdown-title">Qué actividad se observó</h2>
              </div>
              <Link className="summary-section__link" to="/events">Explorar eventos →</Link>
            </div>
            <div className="panels summary-breakdowns">
              <BreakdownList title="Tipos de evento más frecuentes" entries={data.top_event_types} />
              <BreakdownList title="Por categoría" entries={data.by_category} />
              <BreakdownList title="Por resultado" entries={data.by_outcome} />
              <BreakdownList title="Por protocolo" entries={data.by_protocol} />
            </div>
          </section>
        </>
      )}

      {summary.loading ? <p className="state state--loading">Actualizando…</p> : null}
    </div>
  );
}
