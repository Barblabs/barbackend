-- name: ListAreas :many
SELECT record_id, name, owner_email, inactive_since
FROM customer_areas
WHERE cmdb_source_id = @cmdb_source_id
ORDER BY record_id;

-- name: InsertAreas :copyfrom
INSERT INTO customer_areas (cmdb_source_id, record_id, name, inactive_since)
VALUES ($1, $2, $3, $4);

-- name: RenameAreas :batchone
UPDATE customer_areas
SET name = @name,
    imported_changed_at = now()
WHERE cmdb_source_id = @cmdb_source_id AND record_id = @record_id
RETURNING record_id;

-- name: DeactivateAreas :execrows
UPDATE customer_areas
SET inactive_since = coalesce(inactive_since, now())
WHERE cmdb_source_id = @cmdb_source_id AND record_id = ANY(@record_ids::text[]);

-- name: ReactivateAreas :execrows
UPDATE customer_areas
SET inactive_since = NULL
WHERE cmdb_source_id = @cmdb_source_id AND record_id = ANY(@record_ids::text[]);

-- name: DeactivateSourceAreas :exec
UPDATE customer_areas
SET inactive_since = coalesce(inactive_since, now())
WHERE cmdb_source_id = @cmdb_source_id;

-- name: ListCustomerAreas :many
SELECT a.id, a.cmdb_source_id, a.record_id, a.name, a.owner_email, a.inactive_since
FROM customer_areas a
JOIN cmdb_sources s ON s.id = a.cmdb_source_id
WHERE s.customer_id = @customer_id
  AND (sqlc.narg(active)::boolean IS NULL OR (a.inactive_since IS NULL) = sqlc.narg(active)::boolean)
ORDER BY a.name, a.id;

-- name: SetAreaOwner :one
UPDATE customer_areas a
SET owner_email = sqlc.narg(owner_email)
FROM cmdb_sources s
WHERE a.id = @id AND s.id = a.cmdb_source_id AND s.customer_id = @customer_id
RETURNING a.id, a.cmdb_source_id, a.record_id, a.name, a.owner_email, a.inactive_since;
