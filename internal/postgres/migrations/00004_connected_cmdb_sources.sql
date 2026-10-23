-- +goose Up

-- A CMDB Source is connected while disconnected_at is NULL; it is never
-- deleted, so disconnecting only sets it.
ALTER TABLE cmdb_sources ADD COLUMN disconnected_at timestamptz;

-- Every existing source predates stored credentials (00003), so none can
-- sync again. They are disconnected, as a disconnect would, so their
-- Customers can connect a new one.
UPDATE cmdb_sources SET disconnected_at = now() WHERE disconnected_at IS NULL;
UPDATE assets SET inactive_since = now() WHERE inactive_since IS NULL;

CREATE UNIQUE INDEX cmdb_sources_connected_customer_idx ON cmdb_sources (customer_id) WHERE disconnected_at IS NULL;

-- +goose Down
DROP INDEX cmdb_sources_connected_customer_idx;
ALTER TABLE cmdb_sources DROP COLUMN disconnected_at;
