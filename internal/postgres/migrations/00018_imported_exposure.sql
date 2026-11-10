-- +goose Up

-- The Exposure the CMDB Source gives an Asset, beside the declared one; the
-- Declaration wins (ADR 0020). NULL is Unknown, as for declared_exposure_id.
ALTER TABLE assets ADD COLUMN imported_exposure_id smallint REFERENCES exposures (id);

-- +goose Down
ALTER TABLE assets DROP COLUMN imported_exposure_id;
