-- +goose Up

-- Catalog ids equal inventory.SyncOutcome (ADR 0006).
CREATE TABLE sync_outcomes (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO sync_outcomes (id, name) VALUES
    (1, 'Succeeded'),
    (2, 'Failed');

-- skipped_records is [{record_id, reason}]; error is NULL for a successful run.
CREATE TABLE sync_runs (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cmdb_source_id  uuid NOT NULL REFERENCES cmdb_sources (id),
    started_at      timestamptz NOT NULL,
    finished_at     timestamptz NOT NULL,
    outcome_id      smallint NOT NULL REFERENCES sync_outcomes (id),
    created         integer NOT NULL,
    updated         integer NOT NULL,
    deactivated     integer NOT NULL,
    reactivated     integer NOT NULL,
    skipped         integer NOT NULL,
    skipped_records jsonb NOT NULL,
    error           text
);
CREATE INDEX sync_runs_cmdb_source_id_started_at_idx ON sync_runs (cmdb_source_id, started_at DESC);

-- +goose Down
DROP TABLE sync_runs;
DROP TABLE sync_outcomes;
