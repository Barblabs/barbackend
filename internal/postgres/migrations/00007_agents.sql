-- +goose Up

CREATE TABLE feedback_verdicts (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO feedback_verdicts (id, name) VALUES
    (1, 'Applies'),
    (2, 'Does Not Apply'),
    (3, 'Remediated'),
    (4, 'Should Be Earlier'),
    (5, 'Should Be Later');

-- content holds the Dossiers the Prioritizer was given and its Priority
-- Groups. Until Findings are stored, a Finding is the id the Findings pipeline
-- gave it, so finding_id below references nothing.
CREATE TABLE prioritizations (
    id            uuid PRIMARY KEY,
    customer_id   uuid NOT NULL REFERENCES customers (id),
    finding_count integer NOT NULL,
    group_count   integer NOT NULL,
    content       jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX prioritizations_customer_idx ON prioritizations (customer_id, created_at DESC);

CREATE TABLE action_plans (
    id                uuid PRIMARY KEY,
    prioritization_id uuid NOT NULL REFERENCES prioritizations (id),
    finding_id        text NOT NULL,
    content           jsonb NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX action_plans_finding_idx ON action_plans (prioritization_id, finding_id, created_at DESC);

CREATE TABLE prioritization_feedback (
    id                uuid PRIMARY KEY,
    prioritization_id uuid NOT NULL REFERENCES prioritizations (id),
    finding_id        text NOT NULL,
    author_id         uuid NOT NULL REFERENCES users (id),
    verdict_id        smallint NOT NULL REFERENCES feedback_verdicts (id),
    note              text NOT NULL,
    via_analista      boolean NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX prioritization_feedback_idx ON prioritization_feedback (prioritization_id, created_at);

-- json, not jsonb: the history goes back to the model as it was stored.
CREATE TABLE analista_conversations (
    id          uuid PRIMARY KEY,
    customer_id uuid NOT NULL REFERENCES customers (id),
    user_id     uuid NOT NULL REFERENCES users (id),
    history     json NOT NULL,
    turns       integer NOT NULL,
    answering_since timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE analista_conversations;
DROP TABLE prioritization_feedback;
DROP TABLE action_plans;
DROP TABLE prioritizations;
DROP TABLE feedback_verdicts;
