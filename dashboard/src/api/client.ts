/**
 * Thin client for the backend read API.
 *
 * The dashboard only reads, and every request is cancellable so that a filter
 * change cannot leave a stale response on screen.
 */

import type {
  Alert,
  AlertPage,
  AlertStatusChange,
  CommandPage,
  EventPage,
  EventSummary,
  DetectionRuleSet,
  IngestStats,
  NormalizedEvent,
  Order,
  SessionPage,
  SessionTimeline,
  SourceDetail,
  SourcePage,
  TimeBucket,
  TimeSeries,
} from "./types";

const BASE = import.meta.env.VITE_API_BASE_URL ?? "";

export const MAX_LIMIT = 200;

export interface EventQuery {
  eventType?: string;
  sourceIp?: string;
  search?: string;
  category?: string;
  outcome?: string;
  sessionId?: string;
  limit: number;
  offset: number;
  order: Order;
}

export interface AlertQuery {
  ruleId?: string;
  alertType?: string;
  severity?: string;
  sourceIp?: string;
  sessionId?: string;
  status?: string;
  limit: number;
  offset: number;
}

export interface SessionQuery {
  sourceIp?: string;
  username?: string;
  limit: number;
  offset: number;
}

export interface CommandQuery {
  sourceIp?: string;
  sessionId?: string;
  username?: string;
  search?: string;
  limit: number;
  offset: number;
}

export interface SourceQuery {
  limit: number;
  offset: number;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  signal?: AbortSignal,
  init: Pick<RequestInit, "method" | "body"> = {},
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      signal,
      ...init,
      headers: {
        Accept: "application/json",
        ...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
      },
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError(0, "No se pudo contactar al backend. ¿Está en ejecución?");
  }

  if (!response.ok) {
    throw new ApiError(response.status, await describeFailure(response));
  }
  return (await response.json()) as T;
}

async function describeFailure(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as { detail?: unknown };
    if (typeof payload.detail === "string") return payload.detail;
    if (Array.isArray(payload.detail) && payload.detail.length > 0) {
      const first = payload.detail[0] as { msg?: string };
      if (first?.msg) return first.msg;
    }
  } catch {
    // The body was not JSON; fall through to the status text.
  }
  return `El backend respondió ${response.status} ${response.statusText}`.trim();
}

function queryString(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") continue;
    search.set(key, String(value));
  }
  const rendered = search.toString();
  return rendered === "" ? "" : `?${rendered}`;
}

export function fetchSummary(signal?: AbortSignal): Promise<EventSummary> {
  return request<EventSummary>("/api/v1/events/summary", signal);
}

export function fetchIngestStats(signal?: AbortSignal): Promise<IngestStats> {
  return request<IngestStats>("/api/v1/ingest/stats", signal);
}

export function fetchDetectionRules(signal?: AbortSignal): Promise<DetectionRuleSet> {
  return request<DetectionRuleSet>("/api/v1/detections/rules", signal);
}

export function fetchTimeSeries(
  bucket: TimeBucket,
  signal?: AbortSignal,
): Promise<TimeSeries> {
  return request<TimeSeries>(`/api/v1/events/timeseries${queryString({ bucket })}`, signal);
}

export function fetchEventPage(query: EventQuery, signal?: AbortSignal): Promise<EventPage> {
  return request<EventPage>(
    `/api/v1/events${queryString({
      event_type: query.eventType,
      source_ip: query.sourceIp,
      q: query.search,
      event_category: query.category,
      outcome: query.outcome,
      session_id: query.sessionId,
      limit: query.limit,
      offset: query.offset,
      order: query.order,
    })}`,
    signal,
  );
}

export function fetchEvent(
  eventId: string,
  signal?: AbortSignal,
  includeSensitive = false,
): Promise<NormalizedEvent> {
  return request<NormalizedEvent>(
    `/api/v1/events/${encodeURIComponent(eventId)}${queryString({ include_sensitive: includeSensitive ? "true" : undefined })}`,
    signal,
  );
}

export function fetchAlertPage(query: AlertQuery, signal?: AbortSignal): Promise<AlertPage> {
  return request<AlertPage>(
    `/api/v1/alerts${queryString({
      rule_id: query.ruleId,
      alert_type: query.alertType,
      severity: query.severity,
      source_ip: query.sourceIp,
      session_id: query.sessionId,
      status: query.status,
      limit: query.limit,
      offset: query.offset,
    })}`,
    signal,
  );
}

export function fetchAlert(
  alertId: number,
  signal?: AbortSignal,
  includeSensitive = false,
): Promise<Alert> {
  return request<Alert>(
    `/api/v1/alerts/${alertId}${queryString({ include_sensitive: includeSensitive ? "true" : undefined })}`,
    signal,
  );
}

export interface AlertTriageUpdate {
  status: Alert["status"];
  notes: string;
  false_positive_reason?: string;
}

export function updateAlertTriage(
  alertId: number,
  update: AlertTriageUpdate,
  signal?: AbortSignal,
): Promise<Alert> {
  return request<Alert>(`/api/v1/alerts/${alertId}/triage`, signal, {
    method: "PATCH",
    body: JSON.stringify(update),
  });
}

export function fetchAlertHistory(
  alertId: number,
  signal?: AbortSignal,
): Promise<AlertStatusChange[]> {
  return request<AlertStatusChange[]>(`/api/v1/alerts/${alertId}/history`, signal);
}

export function fetchSessionPage(
  query: SessionQuery,
  signal?: AbortSignal,
): Promise<SessionPage> {
  const { sourceIp, username, limit, offset } = query;
  return request<SessionPage>(
    `/api/v1/sessions${queryString({ source_ip: sourceIp, username, limit, offset })}`,
    signal,
  );
}

export function fetchSessionTimeline(
  sessionId: string,
  limit: number,
  offset: number,
  signal?: AbortSignal,
): Promise<SessionTimeline> {
  return request<SessionTimeline>(
    `/api/v1/sessions/${encodeURIComponent(sessionId)}${queryString({ limit, offset })}`,
    signal,
  );
}

export function fetchCommandPage(
  query: CommandQuery,
  signal?: AbortSignal,
): Promise<CommandPage> {
  const { sourceIp, sessionId, username, search, limit, offset } = query;
  return request<CommandPage>(
    `/api/v1/commands${queryString({
      source_ip: sourceIp,
      session_id: sessionId,
      username,
      q: search,
      limit,
      offset,
    })}`,
    signal,
  );
}

export function fetchSourcePage(query: SourceQuery, signal?: AbortSignal): Promise<SourcePage> {
  return request<SourcePage>(
    `/api/v1/sources${queryString({ limit: query.limit, offset: query.offset })}`,
    signal,
  );
}

export function fetchSource(sourceIp: string, signal?: AbortSignal): Promise<SourceDetail> {
  return request<SourceDetail>(`/api/v1/sources/${encodeURIComponent(sourceIp)}`, signal);
}
