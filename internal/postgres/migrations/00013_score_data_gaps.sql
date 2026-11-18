-- +goose Up

-- Inputs a Score was missing and replaced by its Scoring Model's default
-- (ADR 0009), keyed by scoring.DataGap.
CREATE TABLE score_data_gaps (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO score_data_gaps (id, name) VALUES
    (1, 'cvss_estimated'),
    (2, 'epss_pending'),
    (3, 'kev_stale'),
    (4, 'criticality_unknown'),
    (5, 'exposure_undeclared');

-- +goose Down
DROP TABLE score_data_gaps;
