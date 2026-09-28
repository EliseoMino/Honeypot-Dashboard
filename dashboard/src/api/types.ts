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

/**
 * Alert types mirror `honeypot_backend.api.alerts`. The severities and the
 * alert types are the ones the detection rules emit, and the evidence is
 * whatever the rule chose to attach.
 */
export type AlertSeverity = "low" | "medium" | "high" | "critical";

export interface Alert {
  id: number;
  detection_id: number;
  alert_type: string;
  severity: AlertSeverity;
  rule_id: string;
  title: string;
  description: string;
  source_ip: string | null;
  session_id: string | null;
  occurred_from: string;
  occurred_to: string;
  event_count: number;
  evidence: Record<string, unknown>;
  generated_at: string;
}

export interface AlertPage {
  total: number;
  limit: number;
  offset: number;
  items: Alert[];
}

export const ALERT_SEVERITIES: readonly AlertSeverity[] = [
  "low",
  "medium",
  "high",
  "critical",
];

/**
 * The `alert_type` values are the rule *kinds*, not the rule ids: the backend
 * fills the field from `rule_kind` (see `alerts/generation.py`), so
 * `auth_bruteforce` is a `rule_id` and `auth_threshold` is the alert type.
 */
export const ALERT_TYPES: readonly string[] = [
  "auth_threshold",
  "command_of_interest",
  "file_transfer",
];

/** Ordered from most to least severe, which is how the dashboard lists them. */
export const ALERT_SEVERITIES_BY_RANK: readonly AlertSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
];

/** Index of a severity in `ALERT_SEVERITIES_BY_RANK`, where 0 is the worst. */
export function severityRank(severity: AlertSeverity): number {
  const rank = ALERT_SEVERITIES_BY_RANK.indexOf(severity);
  return rank === -1 ? ALERT_SEVERITIES_BY_RANK.length : rank;
}

/** Types mirroring `honeypot_backend.api.sessions` (RF-08). */
export interface SessionSummary {
  session_id: string;
  source_ip: string | null;
  first_seen: string | null;
  last_seen: string | null;
  duration_ms: number | null;
  event_count: number;
  command_count: number;
  usernames: string[];
  protocols: string[];
  has_authentication: boolean;
  has_success: boolean;
}

export interface SessionPage {
  total: number;
  limit: number;
  offset: number;
  items: SessionSummary[];
}

/** Types mirroring `honeypot_backend.api.commands` (RF-09). */
export interface CommandRecord {
  event_id: string;
  event_type: string;
  occurred_at: string | null;
  source_ip: string | null;
  session_id: string | null;
  username: string | null;
  outcome: string | null;
  command: string | null;
  command_line: string | null;
}

export interface CommandPage {
  total: number;
  limit: number;
  offset: number;
  items: CommandRecord[];
}

/** Types mirroring `honeypot_backend.api.sources` (RF-10). */export interface SourceActivity {
  source_ip: string;
  event_count: number;
  session_count: number;
  auth_attempts: number;
  commands: number;
  transfers: number;
  failures: number;
  usernames: string[];
  first_seen: string | null;
  last_seen: string | null;
}

export interface SourcePage {
  total: number;
  limit: number;
  offset: number;
  items: SourceActivity[];
}

export interface SourceDetail extends SourceActivity {
  by_category: CountEntry[];
}

/** Types mirroring `honeypot_backend.api.events` (RF-05). */
export type TimeBucket = "minute" | "hour" | "day";

export interface SeriesPoint {
  bucket: string;
  count: number;
  auth: number;
  commands: number;
}

export interface TimeSeries {
  bucket: TimeBucket;
  points: SeriesPoint[];
}
