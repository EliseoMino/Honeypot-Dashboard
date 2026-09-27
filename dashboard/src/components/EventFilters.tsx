import { useEffect, useState, type FormEvent, type ReactNode } from "react";

import { EVENT_CATEGORIES, EVENT_OUTCOMES } from "../api/types";

export interface EventFilterValues {
  eventType: string;
  sourceIp: string;
  search: string;
  category: string;
  outcome: string;
  sessionId: string;
}

export const EMPTY_FILTERS: EventFilterValues = {
  eventType: "",
  sourceIp: "",
  search: "",
  category: "",
  outcome: "",
  sessionId: "",
};

export function isFiltered(filters: EventFilterValues): boolean {
  return Object.values(filters).some((value) => value !== "");
}

/**
 * The filter form of RF-06: event type, source IP, free text and the two
 * grouped attributes the API already exposes. Fields are combined freely and
 * the session filter is present when the user arrives from an event detail.
 *
 * The form edits a draft and only calls `onApply` on submit, so typing does not
 * issue a request per keystroke.
 */
export function EventFilters({
  value,
  knownTypes,
  onApply,
  onReset,
}: {
  value: EventFilterValues;
  knownTypes: string[];
  onApply: (filters: EventFilterValues) => void;
  onReset: () => void;
}): ReactNode {
  const [draft, setDraft] = useState(value);

  useEffect(() => setDraft(value), [value]);

  const update = (field: keyof EventFilterValues) => (input: string) => {
    setDraft((current) => ({ ...current, [field]: input }));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    onApply({ ...draft, eventType: draft.eventType.trim(), sourceIp: draft.sourceIp.trim() });
  };

  return (
    <form className="filters" onSubmit={submit}>
      <div className="filters__field">
        <label htmlFor="filter-search">Buscar texto</label>
        <input
          id="filter-search"
          type="search"
          placeholder="usuario, comando, sesión…"
          value={draft.search}
          onChange={(event) => update("search")(event.target.value)}
        />
      </div>

      <div className="filters__field">
        <label htmlFor="filter-type">Tipo de evento</label>
        <input
          id="filter-type"
          list="known-event-types"
          placeholder="auth.login_failed"
          value={draft.eventType}
          onChange={(event) => update("eventType")(event.target.value)}
        />
        <datalist id="known-event-types">
          {knownTypes.map((type) => (
            <option key={type} value={type} />
          ))}
        </datalist>
      </div>

      <div className="filters__field">
        <label htmlFor="filter-ip">IP de origen</label>
        <input
          id="filter-ip"
          placeholder="203.0.113.10"
          value={draft.sourceIp}
          onChange={(event) => update("sourceIp")(event.target.value)}
        />
      </div>

      <div className="filters__field">
        <label htmlFor="filter-category">Categoría</label>
        <select
          id="filter-category"
          value={draft.category}
          onChange={(event) => update("category")(event.target.value)}
        >
          <option value="">Todas</option>
          {EVENT_CATEGORIES.map((category) => (
            <option key={category} value={category}>
              {category}
            </option>
          ))}
        </select>
      </div>

      <div className="filters__field">
        <label htmlFor="filter-outcome">Resultado</label>
        <select
          id="filter-outcome"
          value={draft.outcome}
          onChange={(event) => update("outcome")(event.target.value)}
        >
          <option value="">Todos</option>
          {EVENT_OUTCOMES.map((outcome) => (
            <option key={outcome} value={outcome}>
              {outcome}
            </option>
          ))}
        </select>
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
        <button type="button" className="button" onClick={onReset} disabled={!isFiltered(value)}>
          Limpiar
        </button>
      </div>
    </form>
  );
}
