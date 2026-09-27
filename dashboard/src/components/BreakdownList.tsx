import type { ReactNode } from "react";

import type { CountEntry } from "../api/types";
import { formatNumber } from "../utils/format";

/**
 * A labelled counter list, used for the grouped counters of the summary.
 * The bars are proportional to the largest counter.
 */
export function BreakdownList({
  title,
  entries,
  empty = "Sin datos",
}: {
  title: string;
  entries: CountEntry[];
  empty?: string;
}): ReactNode {
  const labelled = entries.filter((entry) => entry.key !== null);
  const largest = labelled.reduce((max, entry) => Math.max(max, entry.count), 0);

  return (
    <section className="panel">
      <h2 className="panel__title">{title}</h2>
      {labelled.length === 0 ? (
        <p className="state state--empty">{empty}</p>
      ) : (
        <ul className="breakdown">
          {labelled.map((entry) => (
            <li key={entry.key} className="breakdown__row">
              <span className="breakdown__label">{entry.key}</span>
              <span className="breakdown__bar" aria-hidden="true">
                <span
                  className="breakdown__fill"
                  style={{ width: `${largest === 0 ? 0 : (entry.count / largest) * 100}%` }}
                />
              </span>
              <span className="breakdown__value">{formatNumber(entry.count)}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
