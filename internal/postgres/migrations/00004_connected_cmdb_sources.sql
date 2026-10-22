-- +goose Up

-- A CMDB Source is connected while disconnected_at is NULL; it is never
-- deleted, so disconnecting only sets it.
ALTER TABLE cmdb_sources ADD COLUMN disconnected_at timestamptz;

-- Existing sources are connected, but a Customer may already have several:
-- only the newest stays connected, so the unique index below can be built.
UPDATE cmdb_sources s
SET disconnected_at = now()
WHERE EXISTS (
    SELECT 1
    FROM cmdb_sources newer
    WHERE newer.customer_id = s.customer_id
      AND (newer.created_at, newer.id) > (s.created_at, s.id)
);

CREATE UNIQUE INDEX cmdb_sources_connected_customer_idx ON cmdb_sources (customer_id) WHERE disconnected_at IS NULL;

-- +goose Down
DROP INDEX cmdb_sources_connected_customer_idx;
ALTER TABLE cmdb_sources DROP COLUMN disconnected_at;
