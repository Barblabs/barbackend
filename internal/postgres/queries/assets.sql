-- Emails must be unique within one call: ON CONFLICT cannot update a row twice
-- in one statement. The no-op update makes RETURNING yield existing owners too.
-- name: UpsertAssetOwners :many
INSERT INTO asset_owners (customer_id, email)
SELECT s.customer_id, e.email
FROM cmdb_sources s, unnest(@emails::text[]) AS e (email)
WHERE s.id = @cmdb_source_id
ON CONFLICT (customer_id, email) DO UPDATE SET email = EXCLUDED.email
RETURNING id, email;

-- COPY cannot call now(), so inactive_since comes from here: the same
-- transaction time the column defaults use.
-- name: TransactionTime :one
SELECT now()::timestamptz;

-- name: InsertAssets :copyfrom
INSERT INTO assets (
    cmdb_source_id, record_id, name, description, kind_id, hardware_vendor, hardware_model,
    criticality_id, imported_owner_id, retired, inactive_since
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: UpdateAssetImported :batchone
UPDATE assets
SET name = @name,
    description = @description,
    kind_id = @kind_id,
    hardware_vendor = @hardware_vendor,
    hardware_model = @hardware_model,
    criticality_id = @criticality_id,
    imported_owner_id = @imported_owner_id,
    retired = @retired,
    imported_changed_at = now()
WHERE cmdb_source_id = @cmdb_source_id AND record_id = @record_id
RETURNING record_id;

-- name: DeactivateAssets :execrows
UPDATE assets
SET inactive_since = coalesce(inactive_since, now())
WHERE cmdb_source_id = @cmdb_source_id AND record_id = ANY(@record_ids::text[]);

-- name: ReactivateAssets :execrows
UPDATE assets
SET inactive_since = NULL
WHERE cmdb_source_id = @cmdb_source_id AND record_id = ANY(@record_ids::text[]);

-- name: ListAssets :many
SELECT a.record_id, a.name, a.description, a.kind_id, a.hardware_vendor, a.hardware_model,
       a.criticality_id, imported_owner.email AS imported_owner, a.retired,
       declared_owner.email AS declared_owner, a.declared_exposure_id,
       (a.inactive_since IS NULL)::boolean AS active
FROM assets a
LEFT JOIN asset_owners imported_owner ON imported_owner.id = a.imported_owner_id
LEFT JOIN asset_owners declared_owner ON declared_owner.id = a.declared_owner_id
WHERE a.cmdb_source_id = @cmdb_source_id
ORDER BY a.record_id;

-- name: DeleteSoftwareComponents :exec
DELETE FROM software_components
WHERE cmdb_source_id = @cmdb_source_id AND record_id = ANY(@record_ids::text[]);

-- name: InsertSoftwareComponents :copyfrom
INSERT INTO software_components (
    cmdb_source_id, record_id, position, role_id, name, version, product_vendor, product_name
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ListSoftwareComponents :many
SELECT record_id, role_id, name, version, product_vendor, product_name
FROM software_components
WHERE cmdb_source_id = @cmdb_source_id
ORDER BY record_id, position;

-- name: DeactivateSourceAssets :exec
UPDATE assets
SET inactive_since = coalesce(inactive_since, now())
WHERE cmdb_source_id = @cmdb_source_id;

-- The keyset condition and the ORDER BY both use (name, cmdb_source_id,
-- record_id), so a page boundary is exact even between equal names.
-- name: ListCustomerAssets :many
SELECT a.cmdb_source_id, a.record_id, a.name, a.description, a.kind_id,
       a.hardware_vendor, a.hardware_model, a.criticality_id,
       imported_owner.email AS imported_owner, declared_owner.email AS declared_owner,
       a.declared_exposure_id, a.retired, a.inactive_since
FROM assets a
JOIN cmdb_sources s ON s.id = a.cmdb_source_id
LEFT JOIN asset_owners imported_owner ON imported_owner.id = a.imported_owner_id
LEFT JOIN asset_owners declared_owner ON declared_owner.id = a.declared_owner_id
WHERE s.customer_id = @customer_id
  AND (sqlc.narg(active)::boolean IS NULL OR (a.inactive_since IS NULL) = sqlc.narg(active)::boolean)
  AND (sqlc.narg(kind_id)::smallint IS NULL OR a.kind_id = sqlc.narg(kind_id)::smallint)
  AND (sqlc.narg(criticality_id)::smallint IS NULL OR a.criticality_id = sqlc.narg(criticality_id)::smallint)
  AND (sqlc.narg(after_name)::text IS NULL
       OR (a.name, a.cmdb_source_id, a.record_id)
          > (sqlc.narg(after_name)::text, sqlc.narg(after_source_id)::uuid, sqlc.narg(after_record_id)::text))
ORDER BY a.name, a.cmdb_source_id, a.record_id
LIMIT @page_size;

-- name: CountCustomerAssets :one
SELECT count(*)
FROM assets a
JOIN cmdb_sources s ON s.id = a.cmdb_source_id
WHERE s.customer_id = @customer_id
  AND (sqlc.narg(active)::boolean IS NULL OR (a.inactive_since IS NULL) = sqlc.narg(active)::boolean)
  AND (sqlc.narg(kind_id)::smallint IS NULL OR a.kind_id = sqlc.narg(kind_id)::smallint)
  AND (sqlc.narg(criticality_id)::smallint IS NULL OR a.criticality_id = sqlc.narg(criticality_id)::smallint);

-- The two arrays are parallel: element i of each names one Asset.
-- name: ListSoftwareComponentsOf :many
SELECT cmdb_source_id, record_id, role_id, name, version, product_vendor, product_name
FROM software_components
WHERE (cmdb_source_id, record_id) IN (
    SELECT s.id, r.id
    FROM unnest(@source_ids::uuid[]) WITH ORDINALITY AS s (id, n)
    JOIN unnest(@record_ids::text[]) WITH ORDINALITY AS r (id, n) USING (n)
)
ORDER BY cmdb_source_id, record_id, position;
