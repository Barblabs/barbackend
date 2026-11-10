-- +goose Up

-- The Score history of a Finding (ADR 0009): its Scoring Model, its value and
-- every factor. A new row is stored only when the model, the value or the Data
-- Gaps differ from the latest one (ADR 0019).
CREATE TABLE finding_scores (
    finding_id             uuid NOT NULL REFERENCES findings (id),
    scored_at              timestamptz NOT NULL,
    model                  smallint NOT NULL CHECK (model > 0),
    value                  double precision NOT NULL CHECK (value BETWEEN 0 AND 1),
    alpha                  double precision NOT NULL CHECK (alpha BETWEEN 0 AND 1),
    beta                   double precision NOT NULL CHECK (beta BETWEEN 0 AND 1),
    gamma                  double precision NOT NULL CHECK (gamma BETWEEN 0 AND 1),
    vulnerability          double precision NOT NULL CHECK (vulnerability BETWEEN 0 AND 1),
    criticality_multiplier double precision NOT NULL CHECK (criticality_multiplier > 0 AND criticality_multiplier <= 1),
    exposure_multiplier    double precision NOT NULL CHECK (exposure_multiplier > 0 AND exposure_multiplier <= 1),
    PRIMARY KEY (finding_id, scored_at)
);

-- +goose Down
DROP TABLE finding_scores;
