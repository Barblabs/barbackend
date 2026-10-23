-- +goose Up

ALTER TABLE cmdb_sources ADD COLUMN credentials bytea NOT NULL DEFAULT '';
ALTER TABLE cmdb_sources ALTER COLUMN credentials DROP DEFAULT;

-- +goose Down
ALTER TABLE cmdb_sources DROP COLUMN credentials;
