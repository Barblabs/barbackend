-- +goose Up

-- Why a Finding's match is uncertain (ADR 0015), keyed by matching.Flag.
CREATE TABLE match_flags (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO match_flags (id, name) VALUES
    (1, 'version_unparsed'),
    (2, 'distro_backport');

-- +goose Down
DROP TABLE match_flags;
