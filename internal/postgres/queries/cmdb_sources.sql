-- name: InsertCMDBSource :exec
INSERT INTO cmdb_sources (id, customer_id, provider, settings, credentials)
VALUES ($1, $2, $3, $4, $5);

-- name: LockCMDBSource :one
SELECT (s.disconnected_at IS NULL)::boolean AS connected,
       (c.deactivated_at IS NOT NULL)::boolean AS customer_deactivated
FROM cmdb_sources s
JOIN customers c ON c.id = s.customer_id
WHERE s.id = $1
FOR UPDATE OF s NOWAIT;

-- name: GetConnectedCMDBSource :one
SELECT id, customer_id, provider, settings, credentials
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
