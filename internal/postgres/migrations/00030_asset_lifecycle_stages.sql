-- +goose Up

-- Where an Asset is in its life, imported from the CMDB Source (ADR 0028).
-- NULL is Unknown; a retired Asset has none.
CREATE TABLE lifecycle_stages (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO lifecycle_stages (id, name) VALUES
    (1, 'Production'),
    (2, 'Implementation'),
    (3, 'Stock');

ALTER TABLE assets ADD COLUMN lifecycle_stage_id smallint REFERENCES lifecycle_stages (id);

-- +goose Down
ALTER TABLE assets DROP COLUMN lifecycle_stage_id;
DROP TABLE lifecycle_stages;
