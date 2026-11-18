-- +goose Up

-- Scoring Model 2 multiplies by the Asset's Lifecycle Stage (ADR 0028).
INSERT INTO score_data_gaps (id, name) VALUES (6, 'lifecycle_unknown');

-- Model 1 had no lifecycle factor, so its Scores keep 1. The default only
-- fills those rows: every new Score states its own multiplier.
ALTER TABLE finding_scores
    ADD COLUMN lifecycle_multiplier double precision NOT NULL DEFAULT 1
        CHECK (lifecycle_multiplier > 0 AND lifecycle_multiplier <= 1);
ALTER TABLE finding_scores ALTER COLUMN lifecycle_multiplier DROP DEFAULT;

-- +goose Down
ALTER TABLE finding_scores DROP COLUMN lifecycle_multiplier;
DELETE FROM finding_score_data_gaps WHERE gap_id = 6;
DELETE FROM score_data_gaps WHERE id = 6;
