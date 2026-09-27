/**
 * Thin client for the backend read API.
 *
 * The dashboard only reads, and every request is cancellable so that a filter
 * change cannot leave a stale response on screen.
 */

import type { EventPage, EventSummary, NormalizedEvent, Order } from "./types";

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

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      signal,
      headers: { Accept: "application/json" },
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

export function fetchEvent(eventId: string, signal?: AbortSignal): Promise<NormalizedEvent> {
  return request<NormalizedEvent>(`/api/v1/events/${encodeURIComponent(eventId)}`, signal);
}
