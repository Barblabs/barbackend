-- +goose Up

-- credentials is ciphertext only the encryption package can open (ADR 0012).
-- Existing sources get none: their settings still name environment
-- variables, which the providers now reject, so 00004 disconnects them.
ALTER TABLE cmdb_sources ADD COLUMN credentials bytea NOT NULL DEFAULT '';
ALTER TABLE cmdb_sources ALTER COLUMN credentials DROP DEFAULT;

-- +goose Down
ALTER TABLE cmdb_sources DROP COLUMN credentials;
