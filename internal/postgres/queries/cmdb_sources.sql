-- name: InsertCMDBSource :exec
INSERT INTO cmdb_sources (id, customer_id, provider, settings, credentials)
VALUES ($1, $2, $3, $4, $5);

-- name: GetCMDBSource :one
SELECT id, customer_id, provider, settings, credentials, (disconnected_at IS NULL)::boolean AS connected
FROM cmdb_sources
WHERE id = $1;

-- name: LockCMDBSource :one
SELECT (disconnected_at IS NULL)::boolean AS connected
FROM cmdb_sources
WHERE id = $1
FOR UPDATE NOWAIT;

-- name: GetConnectedCMDBSource :one
SELECT id, customer_id, provider, settings, credentials, (disconnected_at IS NULL)::boolean AS connected
FROM cmdb_sources
WHERE customer_id = $1 AND disconnected_at IS NULL;

-- name: UpdateConnectedCMDBSourceLogin :execrows
UPDATE cmdb_sources
SET settings = $2, credentials = $3
WHERE id = $1 AND disconnected_at IS NULL;

-- name: LockConnectedCMDBSource :one
SELECT id
FROM cmdb_sources
WHERE customer_id = $1 AND disconnected_at IS NULL
FOR UPDATE NOWAIT;

-- name: DisconnectCMDBSource :exec
UPDATE cmdb_sources
SET disconnected_at = now()
WHERE id = $1;
