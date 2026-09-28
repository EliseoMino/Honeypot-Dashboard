# Architecture

This document describes the technical architecture of Honeypot-Dashboard.

The high-level component overview, the current data flow and the rules for
modifying the system are defined in `/AGENTS.md`.

Content pending: ingestion pipeline, detection and alerting flow, API surface.

## Dashboard (RF-04, RF-06, RF-07)

`/dashboard` is a React 19 + Vite + TypeScript single page application. It is
the only consumer of the read API and it is a pure client: it holds no state of
its own beyond what is on screen, and everything it shows comes from
`/api/v1/events`.

Three routes, one per requirement:

| Route | Requirement | Content |
| --- | --- | --- |
| `/` | RF-04 | The six counters: total events, unique source IPs, sessions, authentication attempts, commands and alerts, plus the time range and the grouped counters |
| `/events` | RF-06 | Ordered, filtered, searchable and paginated event list |
| `/events/:eventId` | RF-07 | Full detail of one event, its session and source IP links, and the original Cowrie payload |

### Filters live in the URL

Every filter, the page size, the offset and the sort direction are query
parameters, so a view can be shared, bookmarked and reached with the back
button. The event detail page uses the same parameters to link to "every event
of this session" and "every event from this IP", which is how RF-07 reaches the
related records.

The list is served by the API with the filters already applied, so the browser
never downloads more than one page. `q` is a free text search; the type filter
is a text input with the known types of the deployment offered as suggestions.

### The alert counter counts raised alerts

`alerts` in `/api/v1/events/summary` counts the alerts of RF-12 that match the
same source IP, session and period as the filtered events. The filters that only
mean something for events, such as the username or the free text search, are not
applied to it.

### Data that refreshes by itself (RF-15)

A monitoring dashboard is left open on a screen, so the numbers on it cannot be
a snapshot taken when the page was opened. The views that show data, the summary
and the event list, refresh in two ways:

- The `Actualizar` button reloads on demand, which is the manual path.
- The `Actualización automática` switch reloads every 10 s, 30 s, 1 min or 5 min,
  which is the periodic path a first version asks for. The choice and the period
  are kept in `localStorage`, because how often somebody wants to watch a
  dashboard is a property of the operator, not of the URL a page is shared
  with. Automatic refresh is on by default, every minute.

`useAutoRefresh` owns the behaviour and the rules are deliberately narrow:

- A tick while a request is still in flight is skipped, so a slow backend cannot
  pile requests up.
- Returning to the tab reloads once, because that is when stale data is most
  visible.
- Turning the switch off removes the timer and the visibility listener, so a
  dashboard read on demand never talks to the backend on its own.

`useResource` reports `updatedAt`, when the data on screen was loaded, and the
controls show it, so an operator can tell a number that is old from one that is
not. A refresh that fails leaves the previous data on screen with the error,
instead of blanking the view.

The event detail page is not refreshed automatically: a stored event does not
change, and the related activity it links to is already one click away.

### Development

```bash
cd dashboard
npm install
npm run dev        # http://localhost:5173, proxies /api to the backend
npm run typecheck
npm test
npm run build
```

The dev server proxies `/api`, `/healthz` and `/readyz` to the backend, so the
browser talks to a single origin and no CORS configuration is needed. Point it
somewhere else with `BACKEND_URL`, for example when the backend runs in Docker
at `http://host.docker.internal:8000`.

`VITE_API_BASE_URL` overrides the API prefix when the dashboard is served from a
different origin than the API, which is the case once a deployment puts them
behind one reverse proxy.

Tests use Vitest with jsdom and Testing Library. There is no browser test:
component behaviour is covered with a recording `fetch` stub, so the assertions
are about what the dashboard requests and renders, not about visual layout. The
refresh tests use fake timers, because the requirement is about time passing.

## Event storage (RF-03)

The storage layer is the hand off between normalization (RF-02) and
everything that reads events afterwards: the dashboard, detection rules and
investigation.

### Schema

`/backend/src/honeypot_backend/db/migrations` holds the schema as plain SQL.
Applied files are recorded in `schema_migrations` and are never re-run; each
file is applied inside a single transaction, so a failure leaves no partial
schema behind. Statements are executed one at a time because asyncpg prepares
every statement and rejects more than one command at a time.

`events` promotes the attributes the system filters on to real columns and
keeps everything else in JSONB:

| Attribute | Column | Type | Notes |
| --- | --- | --- | --- |
| Event time | `occurred_at` | `TIMESTAMPTZ` | When it happened on the honeypot |
| Source IP | `source_ip` | `INET` | Compared as `inet`, never as text |
| Event type | `event_type` | `VARCHAR(128)` | Dotted, for example `auth.login_failed` |
| Session | `session_id` | `VARCHAR(128)` | Cowrie session identifier |
| Details | `details` | `JSONB` | Event specific attributes, normalized names |
| Original | `raw` | `JSONB` | Cowrie payload verbatim, for RF-14 |

RF-03 requires an index on the timestamp, the source IP, the event type and
the session; the migration creates those four plus a `(session_id,
occurred_at)` index for per session timelines and one on the category.

`event_id` is unique. It is derived from the payload, so replaying a batch
after a crash never stores the same event twice.

### Loading

`NormalizedSpoolReplayer` is the only writer of the `events` table. It reads
the normalized spool that the ingestion endpoint writes and keeps the read
position of every file in `spool_cursors`:

- A batch of events and the cursor that follows it are committed together, so
  a crash replays at most one batch, and replays are harmless because inserts
  ignore duplicate `event_id` values.
- If PostgreSQL is unreachable the cursor stays where it is and ingestion keeps
  spooling, so no event is lost while the database is down.
- A spool file that shrank was rotated and is read again from its beginning.

### Reading

`EventRepository` is the only module that talks to the `events` table. It
builds the statements it needs (`insert_statement`, `count_statement`,
`page_statement`) so the SQL can be reviewed and tested without a database.
`/api/v1/events` exposes listing, ordering, filtering, search, pagination and
aggregation, which is the base of RF-06, RF-07 and the dashboard.

## Detection and alerts (RF-11, RF-12)

Two tables sit next to `events`: `detections` records that a rule matched, and
`alerts` reports the match to whoever is watching the dashboard. Both are keyed
by something the data decides, not by a counter, so the same activity cannot be
recorded twice.

### Rules are configuration, not code

`infrastructure/detection/rules.toml` holds every rule, and
`DETECTION_RULES_PATH` points at it. The file is read once, when the backend
starts, with `tomllib` and validated with Pydantic:

- A rule declares `id`, `title`, `description`, `kind` and `severity`, plus the
  parameters its kind needs. The three kinds are `auth_threshold` (several
  authentication attempts from one IP inside a period), `command_of_interest`
  (a command line that invoked a configured executable) and `file_transfer` (a
  file the honeypot was asked to download or to send).
- A configuration problem does not stop the backend: ingestion and the read API
  keep working, `GET /api/v1/detections/rules` reports what is wrong, and
  `POST /api/v1/detections/run` answers 503. Changing the file means restarting
  the backend.

### Rules run on demand

There is no background evaluation. `POST /api/v1/detections/run` evaluates every
rule over a window of stored events and returns what it found, so a run is
reproducible and the answer is never older than the data that was asked about.
`GET /api/v1/detections` reads the stored findings back.

- The window is anchored on the first attempt of a burst of authentication
  attempts, so attempts are never split between two windows and the same burst
  is always recognised as the same one.
- `invoked_commands()` reads the executables a command line really runs: it
  follows pipelines, wrappers such as `sudo`, and the payload of `sh -c`, and it
  reports the executable of each command, never its arguments, so
  `grep wget auth.log` does not match `wget`.
- Findings are sorted by time, rule and fingerprint, so two runs over the same
  data return the same list in the same order.

### A finding is identified, not counted

A detection carries a SHA-256 `fingerprint` built from the rule and the subject
it fired on: the IP and the start of the window for a burst, the event for a
single event. `uq_detections_fingerprint` makes the insert of a finding the
database already knows about a no-op.

That is also what keeps the alerts of RF-12 free of duplicates. An alert is
raised from a stored detection, not from the finding in memory, and
`uq_alerts_detection_id` allows one alert per detection, so evaluating the same
activity again raises nothing.

An alert repeats the activity rather than pointing only at the detection: the
alert type (the kind of the rule that fired), the severity declared by the rule,
the source IP, the session, the span, and the evidence of the detection, in
which `evidence.event_ids` identifies the events that triggered it.
`GET /api/v1/alerts` lists them, the most severe and most recent first, and
`GET /api/v1/alerts/{alert_id}` returns one with its evidence.

The MVP asks for persistence and consultation only, so nothing is sent anywhere:
no email, no Discord, no Telegram.

## Tests

The backend tests in `/backend/tests` run without PostgreSQL: everything that
does not need it still runs, and the rest is skipped. Point
`TEST_DATABASE_URL` at a throwaway database to run everything; the fixtures
drop the schema before and after each test.

```bash
cd backend
python -m pytest                      # no database required
TEST_DATABASE_URL=postgresql+asyncpg://honeypot:change-me@127.0.0.1:5432/honeypot_test python -m pytest
```

To get such a database, `compose.yaml` already has the service, so it is one
variable away and no container to invent:

```bash
POSTGRES_USER=honeypot POSTGRES_PASSWORD=honeypot POSTGRES_DB=honeypot \
  docker compose up -d postgres
docker exec honeypot-dashboard-postgres-1 \
  psql -U honeypot -d honeypot -c 'CREATE DATABASE honeypot_test;'
```

Those tests are the ones that cover the migrations, the JSONB and `INET`
columns and the severity ordering of the alerts, so the RF-11, RF-12 and RF-03
schemas are worth running against a real PostgreSQL before calling any of them
done.

The dashboard tests in `/dashboard/src/test` need no services at all.
