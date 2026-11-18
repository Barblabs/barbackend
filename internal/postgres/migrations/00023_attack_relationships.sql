-- +goose Up

-- How a Mitigation applies to a Technique (mitigates), and which Technique
-- replaced a revoked one (revoked-by) (ADR 0023). No foreign keys: the Feed
-- hands the bundle over in batches, each its own transaction, and a
-- relationship can arrive before the objects it joins.
CREATE TABLE attack_relationships (
    id          text PRIMARY KEY CHECK (id ~ '^relationship--[0-9a-f-]{36}$'),
    type        text NOT NULL CHECK (type IN ('mitigates', 'revoked-by')),
    source_id   text NOT NULL,
    target_id   text NOT NULL,
    description text NOT NULL,
    modified_at timestamptz NOT NULL,
    stored_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX attack_relationships_source ON attack_relationships (type, source_id);
CREATE INDEX attack_relationships_target ON attack_relationships (type, target_id);

-- +goose Down
DROP TABLE attack_relationships;
