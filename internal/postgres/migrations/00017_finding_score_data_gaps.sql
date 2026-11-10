-- +goose Up

-- The Data Gaps of one Score of a Finding; none means every input was known.
CREATE TABLE finding_score_data_gaps (
    finding_id uuid NOT NULL,
    scored_at  timestamptz NOT NULL,
    gap_id     smallint NOT NULL REFERENCES score_data_gaps (id),
    PRIMARY KEY (finding_id, scored_at, gap_id),
    FOREIGN KEY (finding_id, scored_at) REFERENCES finding_scores (finding_id, scored_at)
);

-- +goose Down
DROP TABLE finding_score_data_gaps;
