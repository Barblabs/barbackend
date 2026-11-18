-- +goose Up

-- The Match Flags of a Finding's current match; none means a certain match.
-- They are replaced every time the Finding is matched again.
CREATE TABLE finding_match_flags (
    finding_id uuid NOT NULL REFERENCES findings (id),
    flag_id    smallint NOT NULL REFERENCES match_flags (id),
    PRIMARY KEY (finding_id, flag_id)
);

-- +goose Down
DROP TABLE finding_match_flags;
