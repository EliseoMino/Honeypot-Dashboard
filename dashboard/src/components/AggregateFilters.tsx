import { useEffect, useState, type FormEvent, type ReactNode } from "react";

export interface AggregateFilterValues {
  sourceIp: string;
  sessionId: string;
  search: string;
  username: string;
}

export const EMPTY_AGGREGATE_FILTERS: AggregateFilterValues = {
  sourceIp: "",
  sessionId: "",
  search: "",
  username: "",
};

export function isAggregateFiltered(filters: AggregateFilterValues): boolean {
  return Object.values(filters).some((value) => value !== "");
}

/**
 * The filters shared by the session, command and per IP pages of RF-08, RF-09
 * and RF-10. Each page declares which of the four its endpoint accepts, so the
 * form never offers a field the request would reject: the address page has no
 * session or username to filter by, and the command page has no username
 * column to filter on.
 *
 * The session id is shown as a removable chip when the analyst arrives from an
 * event, a session or a command, because a hidden filter is a confusing one.
 *
 * Like the event and alert filters, the form edits a draft and applies on
 * submit, so typing does not issue a request per keystroke.
 */
export function AggregateFilters({
  value,
  fields,
  onApply,
  onReset,
}: {
  value: AggregateFilterValues;
  fields: readonly (keyof AggregateFilterValues)[];
  onApply: (filters: AggregateFilterValues) => void;
  onReset: () => void;
}): ReactNode {
  const [draft, setDraft] = useState(value);

  useEffect(() => setDraft(value), [value]);

  const update = (field: keyof AggregateFilterValues) => (input: string) => {
    setDraft((current) => ({ ...current, [field]: input }));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    onApply({
      sourceIp: draft.sourceIp.trim(),
      sessionId: draft.sessionId.trim(),
      search: draft.search.trim(),
      username: draft.username.trim(),
    });
  };

  return (
    <form className="filters" onSubmit={submit}>
      {fields.includes("sourceIp") ? (
        <div className="filters__field">
          <label htmlFor="aggregate-ip">IP de origen</label>
          <input
            id="aggregate-ip"
            type="text"
            placeholder="203.0.113.10"
            value={draft.sourceIp}
            onChange={(event) => update("sourceIp")(event.target.value)}
          />
        </div>
      ) : null}

      {fields.includes("username") ? (
        <div className="filters__field">
          <label htmlFor="aggregate-user">Usuario</label>
          <input
            id="aggregate-user"
            type="text"
            placeholder="root"
            value={draft.username}
            onChange={(event) => update("username")(event.target.value)}
          />
        </div>
      ) : null}

      {fields.includes("search") ? (
        <div className="filters__field">
          <label htmlFor="aggregate-search">Texto</label>
          <input
            id="aggregate-search"
            type="text"
            placeholder="wget"
            value={draft.search}
            onChange={(event) => update("search")(event.target.value)}
          />
        </div>
      ) : null}

      {fields.includes("sessionId") && value.sessionId ? (
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
        <button
          type="button"
          className="button"
          onClick={onReset}
          disabled={!isAggregateFiltered(value)}
        >
          Limpiar
        </button>
      </div>
    </form>
  );
}
