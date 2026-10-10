-- name: InsertCMDBSource :exec
INSERT INTO cmdb_sources (id, customer_id, provider, settings)
VALUES ($1, $2, $3, $4);

-- name: GetCMDBSource :one
SELECT id, customer_id, provider, settings
FROM cmdb_sources
WHERE id = $1;

-- name: LockCMDBSource :one
SELECT id
FROM cmdb_sources
WHERE id = $1
FOR UPDATE;
