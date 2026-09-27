/**
 * Types mirroring the backend responses of `/api/v1/events`.
 *
 * They follow `honeypot_backend.api.events` and
 * `honeypot_backend.normalization.events`; keep both in sync.
 */

export type EventCategory =
  | "session"
  | "authentication"
  | "command"
  | "transfer"
  | "client"
  | "other";

export type EventOutcome = "success" | "failure";

export interface NormalizedEvent {
  event_id: string;
  source: string;
  source_event_id: string;
  event_type: string;
  event_category: EventCategory;
  occurred_at: string;
  received_at: string;
  sensor: string | null;
  session_id: string | null;
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  protocol: string | null;
  username: string | null;
  outcome: EventOutcome | null;
  details: Record<string, unknown>;
  raw: Record<string, unknown>;
}

export interface CountEntry {
  key: string | null;
  count: number;
}

export interface EventPage {
  total: number;
  limit: number;
  offset: number;
  items: NormalizedEvent[];
}

export interface EventSummary {
  total_events: number;
  unique_source_ips: number;
  unique_sessions: number;
  unique_usernames: number;
  first_event_at: string | null;
  last_event_at: string | null;
  auth_attempts: number;
  commands: number;
  /** Always 0 until detection rules and alerts (RF-11, RF-12) exist. */
  alerts: number;
  by_category: CountEntry[];
  by_outcome: CountEntry[];
  by_protocol: CountEntry[];
  top_event_types: CountEntry[];
}

export const EVENT_CATEGORIES: readonly EventCategory[] = [
  "session",
  "authentication",
  "command",
  "transfer",
  "client",
  "other",
];

export const EVENT_OUTCOMES: readonly EventOutcome[] = ["success", "failure"];

export type Order = "asc" | "desc";
