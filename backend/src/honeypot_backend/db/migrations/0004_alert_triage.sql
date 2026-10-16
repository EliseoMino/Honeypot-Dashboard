ALTER TABLE alerts
    ADD COLUMN status TEXT NOT NULL DEFAULT 'new',
    ADD COLUMN notes TEXT NOT NULL DEFAULT '',
    ADD COLUMN false_positive_reason TEXT,
    ADD COLUMN status_updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE alerts
    ADD CONSTRAINT ck_alerts_status
    CHECK (status IN ('new', 'in_progress', 'resolved', 'false_positive'));

CREATE TABLE alert_status_history (
    id BIGSERIAL PRIMARY KEY,
    alert_id BIGINT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_alert_status_history_status
        CHECK (new_status IN ('new', 'in_progress', 'resolved', 'false_positive'))
);

