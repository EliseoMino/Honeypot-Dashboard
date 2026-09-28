-- RF-12: alerts raised by the RF-11 detection rules.
--
-- One alert is raised per detection: `detection_id` points at the finding that
-- produced it and is unique, so re-evaluating the same rule over the same
-- activity cannot raise a second alert for the same detection. The activity is
-- kept here as well as in the detection, because an alert is what an operator
-- reads and has to stand on its own.
CREATE TABLE IF NOT EXISTS alerts (
    id             BIGSERIAL PRIMARY KEY,
    -- The RF-11 finding this alert was raised for. ON DELETE CASCADE keeps the
    -- alerts consistent when a detection is removed.
    detection_id   BIGINT      NOT NULL REFERENCES detections (id) ON DELETE CASCADE,
    -- Machine readable type of the alert, the kind of the rule that fired.
    alert_type     VARCHAR(32) NOT NULL,
    severity       VARCHAR(16) NOT NULL,
    rule_id        TEXT        NOT NULL,
    title          TEXT        NOT NULL,
    description    TEXT        NOT NULL DEFAULT '',
    source_ip      INET,
    session_id     VARCHAR(128),
    occurred_from  TIMESTAMPTZ NOT NULL,
    occurred_to    TIMESTAMPTZ NOT NULL,
    event_count    INTEGER     NOT NULL,
    -- The events that triggered the detection, kept so the alert can be
    -- investigated without reading the detection it came from.
    evidence       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    generated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_alerts_detection_id UNIQUE (detection_id),
    CONSTRAINT ck_alerts_severity      CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT ck_alerts_window        CHECK (occurred_to >= occurred_from)
);

CREATE INDEX IF NOT EXISTS ix_alerts_generated_at  ON alerts (generated_at DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_occurred_from ON alerts (occurred_from);
CREATE INDEX IF NOT EXISTS ix_alerts_source_ip     ON alerts (source_ip);
CREATE INDEX IF NOT EXISTS ix_alerts_rule_id       ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS ix_alerts_severity      ON alerts (severity);
