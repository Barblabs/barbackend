-- The no-op update makes RETURNING yield the id of an existing owner too.
-- name: UpsertAssetOwner :one
INSERT INTO asset_owners (customer_id, email)
SELECT s.customer_id, @email
FROM cmdb_sources s
WHERE s.id = @cmdb_source_id
ON CONFLICT (customer_id, email) DO UPDATE SET email = EXCLUDED.email
RETURNING id;

-- name: InsertAsset :exec
INSERT INTO assets (
    cmdb_source_id, record_id, name, description, kind_id, hardware_vendor, hardware_model,
    criticality_id, imported_owner_id, retired, declared_owner_id, declared_exposure_id, inactive_since
) VALUES (
    @cmdb_source_id, @record_id, @name, @description, @kind_id, @hardware_vendor, @hardware_model,
    @criticality_id, @imported_owner_id, @retired, @declared_owner_id, @declared_exposure_id,
    CASE WHEN @active::boolean THEN NULL ELSE now() END
);

-- name: UpdateAssetImported :execrows
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
WHERE cmdb_source_id = @cmdb_source_id AND record_id = @record_id;

-- inactive_since keeps its original time when an Inactive Asset stays Inactive.
-- name: UpdateAssetActive :execrows
UPDATE assets
SET inactive_since = CASE WHEN @active::boolean THEN NULL ELSE coalesce(inactive_since, now()) END
WHERE cmdb_source_id = @cmdb_source_id AND record_id = @record_id;

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
WHERE cmdb_source_id = @cmdb_source_id AND record_id = @record_id;

-- name: InsertSoftwareComponents :copyfrom
INSERT INTO software_components (
    cmdb_source_id, record_id, position, role_id, name, version, product_vendor, product_name
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ListSoftwareComponents :many
SELECT record_id, role_id, name, version, product_vendor, product_name
FROM software_components
WHERE cmdb_source_id = @cmdb_source_id
ORDER BY record_id, position;
