import type { ReactNode } from "react";

import { formatNumber } from "../utils/format";

export function MetricCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: number | null;
  hint?: string;
}): ReactNode {
  return (
    <article className="metric">
      <h3 className="metric__label">{label}</h3>
      <p className="metric__value">{value === null ? "—" : formatNumber(value)}</p>
      {hint ? <p className="metric__hint">{hint}</p> : null}
    </article>
  );
}
