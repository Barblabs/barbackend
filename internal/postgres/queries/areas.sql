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
