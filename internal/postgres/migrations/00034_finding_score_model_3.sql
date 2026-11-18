-- +goose Up

-- Scoring Model 3 weighs the severity by its Exploit Signal and scores the
-- Information Classification (ADR 0032).
INSERT INTO score_data_gaps (id, name) VALUES (7, 'information_classification_undeclared');

-- Both factors are new in Model 3, so the rows of earlier Models keep them
-- null. Which Model has which factor is the Model's, in Go.
ALTER TABLE finding_scores
    ADD COLUMN exploit_signal double precision
        CHECK (exploit_signal BETWEEN 0 AND 1),
    ADD COLUMN information_classification_multiplier double precision
        CHECK (information_classification_multiplier > 0 AND information_classification_multiplier <= 1);

-- +goose Down
ALTER TABLE finding_scores
    DROP COLUMN information_classification_multiplier,
    DROP COLUMN exploit_signal;
DELETE FROM finding_score_data_gaps WHERE gap_id = 7;
DELETE FROM score_data_gaps WHERE id = 7;
