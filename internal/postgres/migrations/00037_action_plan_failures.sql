-- +goose Up

-- How many times Luna, on her own, failed to write the Action Plan of a
-- Finding as one placement of it (ADR 0034). She stops trying at a bound, and
-- a Finding placed again has a new placement, so she tries it anew.
CREATE TABLE action_plan_failures (
    placement_id uuid PRIMARY KEY REFERENCES finding_placements (id),
    attempts     integer NOT NULL CHECK (attempts > 0),
    failed_at    timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE action_plan_failures;
