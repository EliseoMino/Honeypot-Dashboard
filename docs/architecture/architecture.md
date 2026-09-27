# Architecture

This document describes the technical architecture of Honeypot-Dashboard.

The high-level component overview, the current data flow and the rules for
modifying the system are defined in `/AGENTS.md`.

Content pending: component responsibilities, data model, ingestion
pipeline, detection and alerting flow, API surface.

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

## Tests

`/backend/tests` runs without PostgreSQL: everything that does not need it
still runs, and the rest is skipped. Point `TEST_DATABASE_URL` at a
throwaway database to run everything; the fixtures drop the schema before and
after each test.

```bash
cd backend
python -m pytest                      # no database required
TEST_DATABASE_URL=postgresql+asyncpg://honeypot:change-me@127.0.0.1:5432/honeypot_test python -m pytest
```
