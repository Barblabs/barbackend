-- +goose Up

-- The Prioritizations stored until now ordered Dossiers read from files, whose
-- Findings were ids nothing references (ADR 0016), so they cannot be linked to
-- stored Findings.
TRUNCATE prioritization_feedback, action_plans, prioritizations;

-- A Customer's Prioritizations are one chain (ADR 0026): each is built from
-- the one before it, so a Prioritization is the previous one of at most one,
-- and only the first has none. business_context_version is the version of
-- the Business Context its Prioritizer read, null when the Customer had none.
ALTER TABLE prioritizations
    ADD COLUMN previous_id uuid UNIQUE REFERENCES prioritizations (id),
    ADD COLUMN business_context_version integer,
    ADD FOREIGN KEY (customer_id, business_context_version) REFERENCES business_contexts (customer_id, version);
CREATE UNIQUE INDEX prioritizations_first_idx ON prioritizations (customer_id) WHERE previous_id IS NULL;

-- What the Prioritizer read of a Finding when a Prioritization placed it,
-- stored once and kept by every later Prioritization of the chain that keeps
-- the Finding's place. placed_at is when that round read what it placed.
CREATE TABLE finding_placements (
    id         uuid PRIMARY KEY,
    finding_id uuid NOT NULL REFERENCES findings (id),
    placed_at  timestamptz NOT NULL,
    dossier    jsonb NOT NULL,
    UNIQUE (id, finding_id)
);
CREATE INDEX finding_placements_finding_idx ON finding_placements (finding_id);

-- Each Finding of a Prioritization: the position of its Priority Group, where
-- its Score alone would put it, and the placement it has.
CREATE TABLE prioritization_findings (
    prioritization_id uuid NOT NULL REFERENCES prioritizations (id),
    finding_id        uuid NOT NULL REFERENCES findings (id),
    placement_id      uuid NOT NULL,
    group_position    integer NOT NULL,
    score_rank        integer NOT NULL,
    PRIMARY KEY (prioritization_id, finding_id),
    FOREIGN KEY (placement_id, finding_id) REFERENCES finding_placements (id, finding_id)
);
CREATE INDEX prioritization_findings_finding_idx ON prioritization_findings (finding_id);

-- An Action Plan or Feedback is about a Finding of the Prioritization it was
-- asked from, and holds for that Finding in every later one.
DROP INDEX action_plans_finding_idx;
ALTER TABLE action_plans
    ALTER COLUMN finding_id TYPE uuid USING finding_id::uuid,
    ADD FOREIGN KEY (prioritization_id, finding_id) REFERENCES prioritization_findings (prioritization_id, finding_id);
CREATE INDEX action_plans_finding_idx ON action_plans (finding_id, created_at DESC);

DROP INDEX prioritization_feedback_idx;
ALTER TABLE prioritization_feedback
    ALTER COLUMN finding_id TYPE uuid USING finding_id::uuid,
    ADD FOREIGN KEY (prioritization_id, finding_id) REFERENCES prioritization_findings (prioritization_id, finding_id);
CREATE INDEX prioritization_feedback_finding_idx ON prioritization_feedback (finding_id, created_at);

-- +goose Down
DROP INDEX prioritization_feedback_finding_idx;
ALTER TABLE prioritization_feedback
    DROP CONSTRAINT prioritization_feedback_prioritization_id_finding_id_fkey,
    ALTER COLUMN finding_id TYPE text USING finding_id::text;
CREATE INDEX prioritization_feedback_idx ON prioritization_feedback (prioritization_id, created_at);

DROP INDEX action_plans_finding_idx;
ALTER TABLE action_plans
    DROP CONSTRAINT action_plans_prioritization_id_finding_id_fkey,
    ALTER COLUMN finding_id TYPE text USING finding_id::text;
CREATE INDEX action_plans_finding_idx ON action_plans (prioritization_id, finding_id, created_at DESC);

DROP TABLE prioritization_findings;
DROP TABLE finding_placements;
DROP INDEX prioritizations_first_idx;
ALTER TABLE prioritizations
    DROP COLUMN business_context_version,
    DROP COLUMN previous_id;
