-- +goose Up

-- How sensitive the data an Asset holds is, only ever declared (ADR 0031).
-- NULL is Unclassified.
CREATE TABLE information_classifications (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO information_classifications (id, name) VALUES
    (1, 'Public'),
    (2, 'Private'),
    (3, 'Confidential');

ALTER TABLE assets
    ADD COLUMN declared_information_classification_id smallint REFERENCES information_classifications (id),
    ADD COLUMN information_classification_declared_by uuid REFERENCES users (id),
    ADD COLUMN information_classification_declared_at timestamptz,
    ADD CHECK ((declared_information_classification_id IS NULL) = (information_classification_declared_by IS NULL)
               AND (declared_information_classification_id IS NULL) = (information_classification_declared_at IS NULL));

-- +goose Down
ALTER TABLE assets
    DROP COLUMN information_classification_declared_at,
    DROP COLUMN information_classification_declared_by,
    DROP COLUMN declared_information_classification_id;
DROP TABLE information_classifications;
