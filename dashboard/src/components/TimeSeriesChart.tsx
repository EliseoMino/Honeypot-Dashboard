import { useId, useMemo, useState, type ReactNode } from "react";

import type { SeriesPoint, TimeBucket } from "../api/types";
import { formatNumber } from "../utils/format";

const WIDTH = 720;
const HEIGHT = 220;
const PADDING = { top: 16, right: 16, bottom: 34, left: 52 };

/** Enough ticks to orient the reader without turning the axis into a table. */
const MAX_X_TICKS = 6;

const BUCKET_LABELS: Record<TimeBucket, { axis: string; tooltip: string }> = {
  minute: { axis: "HH:mm", tooltip: "dd/MM HH:mm" },
  hour: { axis: "dd/MM HH:mm", tooltip: "dd/MM HH:mm" },
  day: { axis: "dd/MM", tooltip: "dd/MM/yyyy" },
};

const formatterCache = new Map<string, Intl.DateTimeFormat>();

function bucketFormatter(pattern: string): Intl.DateTimeFormat {
  const cached = formatterCache.get(pattern);
  if (cached !== undefined) return cached;
  const created = new Intl.DateTimeFormat("es-ES", {
    day: "2-digit",
    month: "2-digit",
    hour: pattern.includes("HH") ? "2-digit" : undefined,
    minute: pattern.includes("HH") ? "2-digit" : undefined,
    year: pattern.includes("yyyy") ? "numeric" : undefined,
    timeZone: "UTC",
  });
  formatterCache.set(pattern, created);
  return created;
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}
function path(points: readonly { x: number; y: number }[]): string {
  return points.map((point, index) => `${index === 0 ? "M" : "L"}${round(point.x)} ${round(point.y)}`).join(" ");
}

/** The line, closed down to the axis, so the area under it can be filled. */
function areaPath(above: readonly number[], y: (value: number) => number, x: (index: number) => number): string {
  const top = above.map((value, index) => ({ x: x(index), y: y(value) }));
  const last = top[top.length - 1];
  const first = top[0];
  if (first === undefined || last === undefined) return "";
  return `${path(top)} L${round(last.x)} ${round(y(0))} L${round(first.x)} ${round(y(0))} Z`;
}

/**
 * RF-05 — the evolution of the events over time.
 *
 * The series arrives with a point per period that has events, and the periods
 * in between are missing on purpose, so the chart fills the gaps with zeroes to
 * build a continuous axis. Without that, a lull would collapse the axis and the
 * chart would show a flat line through a period of no attacks, which is the
 * exact thing the requirement asks to be able to see.
 *
 * Authentication and commands are drawn as two stacked areas, because those
 * are the two kinds that tell a brute force apart from an interactive session.
 *
 * The chart is hand drawn SVG rather than a charting dependency: the project
 * has no chart library and adding one for one view is not justified.
 */
export function TimeSeriesChart({
  points,
  bucket,
  title,
}: {
  points: SeriesPoint[];
  bucket: TimeBucket;
  title: string;
}): ReactNode {
  const [hovered, setHovered] = useState<number | null>(null);
  const titleId = useId();

  // Guarded on purpose: a response without the array would otherwise throw and
  // take the whole summary page down, and an absent chart is a better outcome
  // than a blank page.
  const series = useMemo(() => fillGaps(points ?? [], bucket), [points, bucket]);

  if (series.length === 0) {
    return (
      <section className="panel">
        <h2 className="panel__title">{title}</h2>
        <p className="state">No hay actividad en el periodo seleccionado.</p>
      </section>
    );
  }

  const innerWidth = WIDTH - PADDING.left - PADDING.right;
  const innerHeight = HEIGHT - PADDING.top - PADDING.bottom;

  const peak = Math.max(...series.map((point) => point.count), 1);
  const step = series.length > 1 ? innerWidth / (series.length - 1) : 0;
  const x = (index: number) => PADDING.left + (series.length > 1 ? index * step : innerWidth / 2);
  const y = (value: number) => PADDING.top + innerHeight - (value / peak) * innerHeight;

  const totals = series.map((point) => point.total);
  const auths = series.map((point) => point.auth);

  const yTicks = [0, 0.5, 1].map((fraction) => ({
    value: Math.round(peak * fraction),
    y: y(peak * fraction),
  }));
  const xTickIndexes = tickIndexes(series.length, MAX_X_TICKS);
  const axisPattern = BUCKET_LABELS[bucket].axis;
  const active = hovered === null ? null : (series[hovered] ?? null);

  return (
    <section className="panel">
      <h2 className="panel__title">{title}</h2>

      <div className="chart">
        <svg
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          className="chart__canvas"
          role="img"
          aria-labelledby={titleId}
          preserveAspectRatio="xMidYMid meet"
        >
          <title id={titleId}>{`${title}: ${formatNumber(totals.reduce((sum, value) => sum + value, 0))} eventos`}</title>

          {yTicks.map((tick) => (
            <g key={tick.value}>
              <line
                className="chart__grid"
                x1={PADDING.left}
                x2={WIDTH - PADDING.right}
                y1={tick.y}
                y2={tick.y}
              />
              <text className="chart__axis" x={PADDING.left - 8} y={tick.y + 4} textAnchor="end">
                {formatNumber(tick.value)}
              </text>
            </g>
          ))}

          <path className="chart__area chart__area--commands" d={areaPath(series.map((point) => point.commands), y, x)} />
          <path className="chart__area chart__area--auth" d={areaPath(auths, y, x)} />
          <path className="chart__line" d={path(totals.map((value, index) => ({ x: x(index), y: y(value) })))} />

          {xTickIndexes.map((index) => (
            <text
              key={series[index]?.bucket ?? index}
              className="chart__axis"
              x={x(index)}
              y={HEIGHT - PADDING.bottom + 18}
              textAnchor="middle"
            >
              {bucketFormatter(axisPattern).format(new Date(series[index]!.at))}
            </text>
          ))}

          {hovered === null ? null : (
            <line
              className="chart__cursor"
              x1={x(hovered)}
              x2={x(hovered)}
              y1={PADDING.top}
              y2={PADDING.top + innerHeight}
            />
          )}

          {series.map((point, index) => (
            <circle
              key={point.bucket}
              className="chart__hit"
              cx={x(index)}
              cy={PADDING.top + innerHeight / 2}
              r={Math.max(step, 12) / 2}
              onMouseEnter={() => setHovered(index)}
              onFocus={() => setHovered(index)}
              onMouseLeave={() => setHovered(null)}
              onBlur={() => setHovered(null)}
              tabIndex={0}
              role="button"
              aria-label={describePoint(point, bucket)}
            />
          ))}
        </svg>

        <ul className="chart__legend">
          <li className="chart__legend-item">
            <span className="chart__swatch chart__swatch--auth" /> Autenticaciones
          </li>
          <li className="chart__legend-item">
            <span className="chart__swatch chart__swatch--commands" /> Comandos
          </li>
          <li className="chart__legend-item">
            <span className="chart__swatch chart__swatch--total" /> Total
          </li>
        </ul>

        {active === null ? (
          <p className="chart__readout">Pasa el cursor por el gráfico para leer un periodo.</p>
        ) : (
          <p className="chart__readout" data-testid="chart-readout">
            <strong>
              {bucketFormatter(BUCKET_LABELS[bucket].tooltip).format(new Date(active.at))}
            </strong>
            {` · ${formatNumber(active.count)} eventos · ${formatNumber(active.auth)} autenticaciones · ${formatNumber(active.commands)} comandos`}
          </p>
        )}
      </div>
    </section>
  );
}

interface DatedPoint extends SeriesPoint {
  at: number;
  total: number;
}

function describePoint(point: DatedPoint, bucket: TimeBucket): string {
  return `${bucketFormatter(BUCKET_LABELS[bucket].tooltip).format(new Date(point.at))}: ${point.count} eventos, ${point.auth} autenticaciones y ${point.commands} comandos`;
}

/**
 * Turn the periods that have events into a continuous axis, filling the gaps
 * with zeroes so a lull reads as a lull.
 */
function fillGaps(points: SeriesPoint[], bucket: TimeBucket): DatedPoint[] {
  const width = bucket === "minute" ? 60_000 : bucket === "hour" ? 3_600_000 : 86_400_000;
  const dated = points
    .map((point) => ({ ...point, at: Date.parse(point.bucket), total: point.count }))
    .filter((point) => Number.isFinite(point.at))
    .sort((left, right) => left.at - right.at);

  if (dated.length <= 1) return dated;

  const filled: DatedPoint[] = [dated[0]!];
  for (let index = 1; index < dated.length; index += 1) {
    const previous = filled[filled.length - 1]!;
    const current = dated[index]!;
    for (let at = previous.at + width; at < current.at; at += width) {
      filled.push({ bucket: new Date(at).toISOString(), count: 0, auth: 0, commands: 0, at, total: 0 });
    }
    filled.push(current);
  }
  return filled;
}

function tickIndexes(length: number, wanted: number): number[] {
  if (length <= wanted) return Array.from({ length }, (_, index) => index);
  const stepSize = Math.ceil((length - 1) / (wanted - 1));
  const indexes: number[] = [];
  for (let index = 0; index < length; index += stepSize) indexes.push(index);
  if (indexes[indexes.length - 1] !== length - 1) indexes.push(length - 1);
  return indexes;
}
