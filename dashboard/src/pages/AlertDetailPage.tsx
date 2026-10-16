import { useEffect, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { fetchAlert, fetchAlertHistory, updateAlertTriage } from "../api/client";
import type { AlertStatus } from "../api/types";
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
  const [showSensitive, setShowSensitive] = useState(false);
  const [triageStatus, setTriageStatus] = useState<AlertStatus>("new");
  const [notes, setNotes] = useState("");
  const [falsePositiveReason, setFalsePositiveReason] = useState("");
  const [triageMessage, setTriageMessage] = useState("");
  const [savingTriage, setSavingTriage] = useState(false);
  const alert = useResource(
    (signal) => fetchAlert(Number(alertId), signal, showSensitive),
    [alertId, showSensitive],
  );
  const history = useResource(
    (signal) => fetchAlertHistory(Number(alertId), signal),
    [alertId],
  );
  useEffect(() => {
    if (alert.data === null) return;
    setTriageStatus(alert.data.status);
    setNotes(alert.data.notes);
    setFalsePositiveReason(alert.data.false_positive_reason ?? "");
  }, [alert.data]);

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
          <h2 className="panel__title">Gestión de la alerta</h2>
          <label className="field">
            <span>Estado</span>
            <select value={triageStatus} onChange={(event) => setTriageStatus(event.target.value as AlertStatus)}>
              <option value="new">Nueva</option>
              <option value="in_progress">En análisis</option>
              <option value="resolved">Resuelta</option>
              <option value="false_positive">Falso positivo</option>
            </select>
          </label>
          {triageStatus === "false_positive" ? (
            <label className="field">
              <span>Motivo del falso positivo</span>
              <input value={falsePositiveReason} maxLength={1000} onChange={(event) => setFalsePositiveReason(event.target.value)} />
            </label>
          ) : null}
          <label className="field">
            <span>Notas del operador</span>
            <textarea value={notes} maxLength={4000} rows={4} onChange={(event) => setNotes(event.target.value)} />
          </label>
          <button
            type="button"
            className="button"
            disabled={savingTriage || (triageStatus === "false_positive" && !falsePositiveReason.trim())}
            onClick={async () => {
              setSavingTriage(true);
              setTriageMessage("");
              try {
                await updateAlertTriage(Number(alertId), {
                  status: triageStatus,
                  notes,
                  false_positive_reason: triageStatus === "false_positive" ? falsePositiveReason : undefined,
                });
                await alert.reload();
                setTriageMessage("Cambios guardados.");
              } catch (error) {
                setTriageMessage(error instanceof Error ? error.message : "No se pudieron guardar los cambios.");
              } finally {
                setSavingTriage(false);
              }
            }}
          >
            {savingTriage ? "Guardando…" : "Guardar gestión"}
          </button>
          {triageMessage ? <p role="status">{triageMessage}</p> : null}
          <h3>Historial de estados</h3>
          {history.data?.length ? (
            <ul className="evidence-list">
              {history.data.map((change, index) => (
                <li key={`${change.changed_at}-${index}`}>
                  {change.previous_status ?? "—"} → {change.new_status} · {formatDateTime(change.changed_at)}
                  {change.note ? <p>{change.note}</p> : null}
                </li>
              ))}
            </ul>
          ) : <p className="page__subtitle">Sin cambios de estado registrados.</p>}
        </section>
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
        <div className="panel__header">
          <h2 className="panel__title">Evidencia de la regla</h2>
          <button
            type="button"
            className="button button--ghost"
            onClick={() => setShowSensitive((value) => !value)}
            aria-expanded={showSensitive}
          >
            {showSensitive ? "Ocultar evidencia completa" : "Revelar evidencia completa"}
          </button>
        </div>
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
