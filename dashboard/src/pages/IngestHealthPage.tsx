import type { ReactNode } from "react";

import { fetchIngestStats } from "../api/client";
import { ErrorBanner, Loading } from "../components/Feedback";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatNumber } from "../utils/format";

function bytes(value: number | null): string {
  if (value === null) return "No disponible";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function IngestHealthPage(): ReactNode {
  const resource = useResource((signal) => fetchIngestStats(signal), []);
  if (resource.error !== null) {
    return <div className="page"><ErrorBanner message={resource.error} onRetry={resource.reload} /></div>;
  }
  if (resource.data === null) return <Loading label="Consultando la ingesta" />;
  const { metrics, replayer, storage } = resource.data;
  return (
    <div className="page">
      <header className="page__header">
        <div><h1>Salud de ingesta</h1><p className="page__subtitle">Agente, reproducción del spool y uso de almacenamiento.</p></div>
        <button type="button" className="button" onClick={resource.reload}>Actualizar</button>
      </header>
      <div className="metrics">
        <Metric label="Último lote recibido" value={formatDateTime(metrics.last_batch_at)} />
        <Metric label="Eventos recibidos" value={formatNumber(metrics.events_received)} />
        <Metric label="Eventos rechazados" value={formatNumber(metrics.events_rejected)} />
        <Metric label="Saltos de secuencia" value={formatNumber(metrics.sequence_gaps)} />
        <Metric label="Spool persistido" value={bytes(storage.spool_bytes)} />
        <Metric label="Datos de Cowrie" value={bytes(storage.cowrie_data_bytes)} />
        <Metric label="Espacio libre" value={bytes(storage.filesystem.free_bytes)} />
        <Metric label="Log Cowrie actualizado" value={formatDateTime(storage.cowrie_log.modified_at)} />
      </div>
      <section className="panel">
        <h2 className="panel__title">Estado del replayer</h2>
        {replayer === null ? <p>No hay replayer configurado.</p> : (
          <dl className="attributes">
            <Row label="Eventos cargados">{formatNumber(replayer.events_loaded)}</Row>
            <Row label="Líneas malformadas">{formatNumber(replayer.malformed_lines)}</Row>
            <Row label="Fallos de reproducción">{formatNumber(replayer.failures)}</Row>
            <Row label="Evaluaciones automáticas">{formatNumber(replayer.auto_detection_runs)}</Row>
            <Row label="Fallos de detección automática">{formatNumber(replayer.auto_detection_failures)}</Row>
          </dl>
        )}
        <p className="page__subtitle">El último lote refleja actividad Cowrie, no un heartbeat del agente; un honeypot inactivo puede no enviar lotes. Los contadores de proceso vuelven a cero al reiniciar el backend. No se borran automáticamente logs ni eventos pendientes.</p>
      </section>
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }): ReactNode {
  return <div className="attributes__row"><dt>{label}</dt><dd>{children}</dd></div>;
}

function Metric({ label, value }: { label: string; value: string }): ReactNode {
  return <article className="metric"><h3 className="metric__label">{label}</h3><p className="metric__value">{value}</p></article>;
}
