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
  const { metrics, replayer, storage, agents } = resource.data;
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
        <Metric label="Agente" value={agents.length === 0 ? "Sin heartbeat" : agents.every((agent) => agent.status === "active") ? "Activo" : "Atrasado"} />
        <Metric label="Último heartbeat" value={agents.length ? formatDateTime(agents.map((agent) => agent.last_heartbeat_at).sort().at(-1)) : "Nunca"} />
        <Metric label="Spool persistido" value={bytes(storage.spool_bytes)} />
        <Metric label="Datos de Cowrie" value={bytes(storage.cowrie_data_bytes)} />
        <Metric label="Espacio libre" value={bytes(storage.filesystem.free_bytes)} />
        <Metric label="Log Cowrie actualizado" value={formatDateTime(storage.cowrie_log.modified_at)} />
      </div>
      {agents.length > 0 ? (
        <section className="panel">
          <h2 className="panel__title">Agentes de ingesta</h2>
          <div className="table-wrapper">
            <table className="table">
              <thead><tr><th>Agente</th><th>Estado</th><th>Último heartbeat</th><th>Offset / tamaño log</th><th>Pendientes</th><th>Malformadas</th><th>Fallos de entrega</th><th>Rotaciones / truncamientos</th></tr></thead>
              <tbody>{agents.map((agent) => <tr key={agent.agent_id}>
                <td className="table__mono">{agent.agent_id}</td>
                <td><span className={`badge badge--${agent.status === "active" ? "low" : "high"}`}>{agent.status === "active" ? "activo" : "sin señal reciente"}</span></td>
                <td>{formatDateTime(agent.last_heartbeat_at)} ({agent.age_seconds} s)</td>
                <td>{bytes(agent.log_offset)} / {bytes(agent.log_size_bytes)}</td>
                <td>{formatNumber(agent.pending_records)}</td>
                <td>{formatNumber(agent.malformed_lines)}</td>
                <td>{formatNumber(agent.delivery_failures)}</td>
                <td>{formatNumber(agent.rotations)} / {formatNumber(agent.truncations)}{agent.truncations > 0 ? <span className="badge badge--high"> posible pérdida</span> : null}</td>
              </tr>)}</tbody>
            </table>
          </div>
        </section>
      ) : null}
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
        <p className="page__subtitle">El heartbeat confirma que el agente se comunica con el backend; no garantiza que Cowrie genere eventos. Las métricas de ingesta se conservan en el volumen persistente del spool. No se borran automáticamente logs ni eventos pendientes.</p>
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
