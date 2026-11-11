-- +goose Up

-- The ATT&CK Techniques, stored whole as reference data (ADR 0023): revoked
-- and deprecated ones too, so a label from an older ATT&CK version still
-- reaches its Technique or its replacement. Shared by every Customer.
CREATE TABLE attack_techniques (
    id          text PRIMARY KEY CHECK (id ~ '^attack-pattern--[0-9a-f-]{36}$'),
    attack_id   text NOT NULL UNIQUE CHECK (attack_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
    name        text NOT NULL,
    tactics     text[] NOT NULL,
    revoked     boolean NOT NULL,
    deprecated  boolean NOT NULL,
    object      jsonb NOT NULL,
    modified_at timestamptz NOT NULL,
    stored_at   timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE attack_techniques;
