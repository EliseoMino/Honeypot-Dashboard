import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { formatNumber } from "../utils/format";

export function MetricCard({
  label,
  value,
  hint,
  to,
}: {
  label: string;
  value: number | null;
  hint?: string;
  to?: string;
}): ReactNode {
  const content = (
    <>
      <h3 className="metric__label">{label}</h3>
      <p className="metric__value">{value === null ? "—" : formatNumber(value)}</p>
      {hint ? <p className="metric__hint">{hint}</p> : null}
    </>
  );

  return to ? (
    <Link className="metric metric--link" to={to} aria-label={`${label}: ${value ?? "sin datos"}. Ver detalles`}>
      {content}
      <span className="metric__action" aria-hidden="true">Ver detalles →</span>
    </Link>
  ) : (
    <article className="metric">{content}</article>
  );
}
