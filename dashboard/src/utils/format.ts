/** Formatting helpers shared by the views. */

const DATE_TIME = new Intl.DateTimeFormat("es-ES", {
  dateStyle: "short",
  timeStyle: "medium",
  timeZone: "UTC",
});

const TIME_ONLY = new Intl.DateTimeFormat("es-ES", {
  timeStyle: "medium",
  timeZone: "UTC",
});

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : `${DATE_TIME.format(parsed)} UTC`;
}

export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : TIME_ONLY.format(parsed);
}

export function formatNumber(value: number | null | undefined): string {
  return new Intl.NumberFormat("es-ES").format(value ?? 0);
}

export function formatEndpoint(ip: string | null, port: number | null): string {
  if (ip === null) return "—";
  return port === null ? ip : `${ip}:${port}`;
}

/** Render a JSONB value as a single line, for table cells. */
export function previewValue(value: unknown, maxLength = 90): string {
  if (value === null || value === undefined) return "";
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (text === undefined) return String(value);
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}
