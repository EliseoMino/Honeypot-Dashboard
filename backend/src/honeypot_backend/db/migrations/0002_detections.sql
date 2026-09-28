-- RF-11: findings of the detection rules.
--
-- A detection is the record of one rule matching. It keeps the rule that fired,
-- the subject it fired on (source IP and session), the span of time the rule
-- looked at, and the evidence: the events that triggered it. Alerts (RF-12) are
-- generated from these rows later; the table is named for what it stores today.
CREATE TABLE IF NOT EXISTS detections (
    id            BIGSERIAL PRIMARY KEY,
    rule_id       TEXT        NOT NULL,
    rule_kind     VARCHAR(32) NOT NULL,
    title         TEXT        NOT NULL,
    source_ip     INET,
    session_id    VARCHAR(128),
    occurred_from TIMESTAMPTZ NOT NULL,
    occurred_to   TIMESTAMPTZ NOT NULL,
    event_count   INTEGER     NOT NULL,
    evidence      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- Deterministic identity of the finding, so evaluating the same rule over
    -- the same data twice never stores it twice.
    fingerprint   TEXT        NOT NULL,
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_detections_fingerprint UNIQUE (fingerprint),
    CONSTRAINT ck_detections_window      CHECK (occurred_to >= occurred_from)
);

CREATE INDEX IF NOT EXISTS ix_detections_rule_id       ON detections (rule_id);
CREATE INDEX IF NOT EXISTS ix_detections_source_ip     ON detections (source_ip);
CREATE INDEX IF NOT EXISTS ix_detections_occurred_from ON detections (occurred_from);
CREATE INDEX IF NOT EXISTS ix_detections_detected_at   ON detections (detected_at DESC);
