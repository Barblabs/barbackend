-- +goose Up

-- Why a Finding was closed (ADR 0019), keyed by matching.CloseReason.
CREATE TABLE finding_close_reasons (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO finding_close_reasons (id, name) VALUES
    (1, 'no_longer_affected'),
    (2, 'component_removed'),
    (3, 'asset_inactive'),
    (4, 'vulnerability_rejected');

-- +goose Down
DROP TABLE finding_close_reasons;
