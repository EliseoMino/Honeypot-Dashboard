import type { ReactNode } from "react";

import { formatNumber } from "../utils/format";

const PAGE_SIZES = [25, 50, 100] as const;

/** Page navigation for the event list (RF-06). */
export function Pagination({
  total,
  limit,
  offset,
  onOffsetChange,
  onLimitChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onOffsetChange: (offset: number) => void;
  onLimitChange: (limit: number) => void;
}): ReactNode {
  const first = total === 0 ? 0 : offset + 1;
  const last = Math.min(offset + limit, total);
  const page = limit === 0 ? 1 : Math.floor(offset / limit) + 1;
  const pages = limit === 0 ? 1 : Math.max(1, Math.ceil(total / limit));

  return (
    <nav className="pagination" aria-label="Paginación de eventos">
      <p className="pagination__summary">
        {formatNumber(first)}–{formatNumber(last)} de {formatNumber(total)} · página{" "}
        {formatNumber(page)} de {formatNumber(pages)}
      </p>

      <div className="pagination__controls">
        <label className="pagination__size">
          Filas
          <select
            value={limit}
            onChange={(event) => onLimitChange(Number(event.target.value))}
          >
            {PAGE_SIZES.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          className="button"
          onClick={() => onOffsetChange(Math.max(0, offset - limit))}
          disabled={offset === 0}
        >
          Anterior
        </button>
        <button
          type="button"
          className="button"
          onClick={() => onOffsetChange(offset + limit)}
          disabled={offset + limit >= total}
        >
          Siguiente
        </button>
      </div>
    </nav>
  );
}
