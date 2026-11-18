-- +goose Up

-- One row per outbound Slack message, the DM and the channel copy separately
-- (ADR 0030). The pipeline inserts rows and the worker drains them, so this
-- table only holds work that is pending or has failed.
CREATE TABLE slack_deliveries (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id     uuid NOT NULL REFERENCES customers (id),
    kind            text NOT NULL,
    target_kind     text NOT NULL CHECK (target_kind IN ('email', 'channel')),
    target          text NOT NULL,
    payload         jsonb NOT NULL,
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    failure_code    text,
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- The worker claims due rows, oldest first.
CREATE INDEX slack_deliveries_due ON slack_deliveries (next_attempt_at, created_at)
    WHERE status = 'pending';

-- The portal lists a Customer's failed rows.
CREATE INDEX slack_deliveries_failed ON slack_deliveries (customer_id, created_at)
    WHERE status = 'failed';

-- +goose Down
DROP TABLE slack_deliveries;
