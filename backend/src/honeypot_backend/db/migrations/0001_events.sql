-- RF-03: storage for normalized Cowrie events.
CREATE TABLE IF NOT EXISTS events (
    id                BIGSERIAL PRIMARY KEY,
    event_id          TEXT        NOT NULL,
    source            VARCHAR(32) NOT NULL,
    source_event_id   VARCHAR(128) NOT NULL,
    event_type        VARCHAR(128) NOT NULL,
    event_category    VARCHAR(32)  NOT NULL,
    occurred_at       TIMESTAMPTZ NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL,
    sensor            VARCHAR(256),
    session_id        VARCHAR(128),
    source_ip         INET,
    source_port       INTEGER,
    destination_ip    INET,
    destination_port  INTEGER,
    protocol          VARCHAR(16),
    username          VARCHAR(256),
    outcome           VARCHAR(16),
    details           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    raw               JSONB       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT uq_events_event_id UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS ix_events_occurred_at           ON events (occurred_at);
CREATE INDEX IF NOT EXISTS ix_events_source_ip             ON events (source_ip);
CREATE INDEX IF NOT EXISTS ix_events_event_type            ON events (event_type);
CREATE INDEX IF NOT EXISTS ix_events_session_id            ON events (session_id);
CREATE INDEX IF NOT EXISTS ix_events_session_occurred_at   ON events (session_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_events_event_category        ON events (event_category);

-- Read position of the normalized spool, so loading into PostgreSQL resumes
-- exactly where it stopped.
CREATE TABLE IF NOT EXISTS spool_cursors (
    path       TEXT        PRIMARY KEY,
    offset     BIGINT      NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
