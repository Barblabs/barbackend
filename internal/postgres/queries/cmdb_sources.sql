-- name: InsertCMDBSource :exec
INSERT INTO cmdb_sources (id, customer_id, provider, settings, credentials)
VALUES ($1, $2, $3, $4, $5);

-- name: GetCMDBSource :one
SELECT id, customer_id, provider, settings, credentials
FROM cmdb_sources
WHERE id = $1;

-- NOWAIT fails at once instead of queueing behind a Sync that may never end.
-- name: LockCMDBSource :one
SELECT id
FROM cmdb_sources
WHERE id = $1
FOR UPDATE NOWAIT;

-- name: GetConnectedCMDBSource :one
SELECT id, customer_id, provider, settings, credentials
FROM cmdb_sources
WHERE customer_id = $1 AND disconnected_at IS NULL;
