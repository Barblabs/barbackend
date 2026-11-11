-- +goose Up

-- The ATT&CK Mitigations, the course-of-actions with an M id (ADR 0023).
-- Shared by every Customer.
CREATE TABLE attack_mitigations (
    id          text PRIMARY KEY CHECK (id ~ '^course-of-action--[0-9a-f-]{36}$'),
    attack_id   text NOT NULL UNIQUE CHECK (attack_id ~ '^M[0-9]{4}$'),
    name        text NOT NULL,
    object      jsonb NOT NULL,
    modified_at timestamptz NOT NULL,
    stored_at   timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE attack_mitigations;
