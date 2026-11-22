-- +goose Up

-- Highly Confidential, a step above Confidential, scored from Scoring Model 4
-- (ADR 0037).
INSERT INTO information_classifications (id, name) VALUES (4, 'Highly Confidential');

-- +goose Down
-- Assets declared Highly Confidential keep the nearest declaration there is.
UPDATE assets SET declared_information_classification_id = 3 WHERE declared_information_classification_id = 4;
DELETE FROM information_classifications WHERE id = 4;
