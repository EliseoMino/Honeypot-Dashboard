import { useEffect, useState, type FormEvent, type ReactNode } from "react";

import { ALERT_SEVERITIES, ALERT_TYPES } from "../api/types";

export interface AlertFilterValues {
  severity: string;
  alertType: string;
  ruleId: string;
  sourceIp: string;
  sessionId: string;
}

export const EMPTY_ALERT_FILTERS: AlertFilterValues = {
  severity: "",
  alertType: "",
  ruleId: "",
  sourceIp: "",
  sessionId: "",
};

export function isAlertFiltered(filters: AlertFilterValues): boolean {
  return Object.values(filters).some((value) => value !== "");
}

/**
 * The filters of RF-13, restricted to what the alerts API accepts. Severity and
 * alert type are selects because the API validates them, so offering a free
 * text field for them would only let the request fail.
 *
 * Like the event filters, the form edits a draft and applies on submit.
 */
export function AlertFilters({
  value,
  onApply,
  onReset,
}: {
  value: AlertFilterValues;
  onApply: (filters: AlertFilterValues) => void;
  onReset: () => void;
}): ReactNode {
  const [draft, setDraft] = useState(value);

  useEffect(() => setDraft(value), [value]);

  const update = (field: keyof AlertFilterValues) => (input: string) => {
    setDraft((current) => ({ ...current, [field]: input }));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    onApply({ ...draft, ruleId: draft.ruleId.trim(), sourceIp: draft.sourceIp.trim() });
  };

  return (
    <form className="filters" onSubmit={submit}>
      <div className="filters__field">
        <label htmlFor="alert-severity">Severidad</label>
        <select
          id="alert-severity"
          value={draft.severity}
          onChange={(event) => update("severity")(event.target.value)}
        >
          <option value="">Todas</option>
          {ALERT_SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {severity}
            </option>
          ))}
        </select>
      </div>

      <div className="filters__field">
        <label htmlFor="alert-type">Tipo de alerta</label>
        <select
          id="alert-type"
          value={draft.alertType}
          onChange={(event) => update("alertType")(event.target.value)}
        >
          <option value="">Todos</option>
          {ALERT_TYPES.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
      </div>

      <div className="filters__field">
        <label htmlFor="alert-rule">Regla</label>
        <input
          id="alert-rule"
          type="text"
          placeholder="auth_bruteforce"
          value={draft.ruleId}
          onChange={(event) => update("ruleId")(event.target.value)}
        />
      </div>

      <div className="filters__field">
        <label htmlFor="alert-ip">IP de origen</label>
        <input
          id="alert-ip"
          placeholder="203.0.113.10"
          value={draft.sourceIp}
          onChange={(event) => update("sourceIp")(event.target.value)}
        />
      </div>

      {value.sessionId ? (
        <div className="filters__field filters__field--chip">
          <span className="filters__chip-label">Sesión</span>
          <span className="filters__chip">{value.sessionId}</span>
          <button
            type="button"
            className="button button--ghost"
            onClick={() => onApply({ ...value, sessionId: "" })}
          >
            Quitar
          </button>
        </div>
      ) : null}

      <div className="filters__actions">
        <button type="submit" className="button button--primary">
          Aplicar
        </button>
        <button type="button" className="button" onClick={onReset} disabled={!isAlertFiltered(value)}>
          Limpiar
        </button>
      </div>
    </form>
  );
}
