-- The Software Components of Active Assets that have one of the Products,
-- compared in lower case and trimmed, with what scoring needs of their Asset.
-- The two arrays are parallel: element i of each names one Product, already
-- in lower case.
-- name: ListActiveComponentsWithProducts :many
SELECT c.cmdb_source_id, c.record_id, c.position, c.role_id, c.name, c.version,
       c.product_vendor, c.product_name, a.criticality_id,
       coalesce(a.declared_exposure_id, a.imported_exposure_id) AS exposure_id
FROM software_components c
JOIN assets a USING (cmdb_source_id, record_id)
WHERE a.inactive_since IS NULL
  AND (lower(btrim(c.product_vendor)), lower(btrim(c.product_name))) IN (
      SELECT vendor.value, product.value
      FROM unnest(@vendors::text[]) WITH ORDINALITY AS vendor (value, n)
      JOIN unnest(@products::text[]) WITH ORDINALITY AS product (value, n) USING (n)
  )
ORDER BY c.cmdb_source_id, c.record_id, c.position;

-- The Software Components of a CMDB Source's Active Assets, with what scoring
-- needs of their Asset.
-- name: ListActiveComponentsOfSource :many
SELECT c.cmdb_source_id, c.record_id, c.position, c.role_id, c.name, c.version,
       c.product_vendor, c.product_name, a.criticality_id,
       coalesce(a.declared_exposure_id, a.imported_exposure_id) AS exposure_id
FROM software_components c
JOIN assets a USING (cmdb_source_id, record_id)
WHERE a.inactive_since IS NULL AND c.cmdb_source_id = @cmdb_source_id
ORDER BY c.cmdb_source_id, c.record_id, c.position;

-- Opens, updates or reopens the Finding of one match in one statement, so two
-- matches of the same Finding at once cannot both insert it. previous is read
-- before the statement runs, so it tells what the Finding was: absent (opened),
-- open (updated) or closed (reopened). Times are the transaction's, so
-- first_opened_at <= opened_at holds whatever the application's clock says.
-- name: UpsertFinding :one
WITH previous AS (
    SELECT f.closed_at
    FROM findings f
    WHERE f.cmdb_source_id = @cmdb_source_id AND f.record_id = @record_id
      AND f.product_vendor = @product_vendor AND f.product_name = @product_name
      AND f.cve_id = @cve_id
)
INSERT INTO findings (
    id, cmdb_source_id, record_id, product_vendor, product_name, cve_id,
    component_name, component_version, evidence, first_opened_at, opened_at
) VALUES (
    @id, @cmdb_source_id, @record_id, @product_vendor, @product_name, @cve_id,
    @component_name, @component_version, @evidence, now(), now()
)
ON CONFLICT (cmdb_source_id, record_id, product_vendor, product_name, cve_id) DO UPDATE
SET component_name    = EXCLUDED.component_name,
    component_version = EXCLUDED.component_version,
    evidence          = EXCLUDED.evidence,
    opened_at         = CASE WHEN findings.closed_at IS NULL THEN findings.opened_at ELSE now() END,
    closed_at         = NULL,
    close_reason_id   = NULL
RETURNING findings.id,
          (SELECT count(*) FROM previous)::int AS existed,
          coalesce((SELECT bool_or(p.closed_at IS NOT NULL) FROM previous p), false)::boolean AS was_closed;

-- name: CloseFinding :execrows
UPDATE findings
SET closed_at = now(), close_reason_id = @close_reason_id
WHERE id = @id AND closed_at IS NULL;

-- Closes the open Findings of the source's Assets that are Inactive.
-- name: CloseFindingsOfInactiveAssets :execrows
UPDATE findings f
SET closed_at = now(), close_reason_id = @close_reason_id
FROM assets a
WHERE a.cmdb_source_id = f.cmdb_source_id AND a.record_id = f.record_id
  AND f.cmdb_source_id = @cmdb_source_id
  AND a.inactive_since IS NOT NULL
  AND f.closed_at IS NULL;

-- The open Findings of one Vulnerability, with what scoring needs of their Asset.
-- name: ListOpenFindingsOfVulnerability :many
SELECT f.id, f.cmdb_source_id, f.record_id, f.product_vendor, f.product_name, f.cve_id,
       f.component_name, f.component_version, a.criticality_id,
       coalesce(a.declared_exposure_id, a.imported_exposure_id) AS exposure_id
FROM findings f
JOIN assets a USING (cmdb_source_id, record_id)
WHERE f.cve_id = @cve_id AND f.closed_at IS NULL
ORDER BY f.cmdb_source_id, f.record_id, f.product_vendor, f.product_name;

-- The open Findings of a CMDB Source's Assets, with what scoring needs of
-- their Asset.
-- name: ListOpenFindingsOfSource :many
SELECT f.id, f.cmdb_source_id, f.record_id, f.product_vendor, f.product_name, f.cve_id,
       f.component_name, f.component_version, a.criticality_id,
       coalesce(a.declared_exposure_id, a.imported_exposure_id) AS exposure_id
FROM findings f
JOIN assets a USING (cmdb_source_id, record_id)
WHERE f.closed_at IS NULL AND f.cmdb_source_id = @cmdb_source_id
ORDER BY f.cmdb_source_id, f.record_id, f.product_vendor, f.product_name, f.cve_id;

-- name: DeleteFindingMatchFlags :exec
DELETE FROM finding_match_flags
WHERE finding_id = @finding_id;

-- name: InsertFindingMatchFlags :copyfrom
INSERT INTO finding_match_flags (finding_id, flag_id) VALUES ($1, $2);

-- name: ListFindingMatchFlags :many
SELECT flag_id
FROM finding_match_flags
WHERE finding_id = @finding_id
ORDER BY flag_id;

-- The latest Score of a Finding, with its Data Gaps in catalog order.
-- name: LatestFindingScore :one
SELECT s.scored_at, s.model, s.value, s.alpha, s.beta, s.gamma, s.vulnerability,
       s.criticality_multiplier, s.exposure_multiplier,
       coalesce(array_agg(g.gap_id ORDER BY g.gap_id) FILTER (WHERE g.gap_id IS NOT NULL), '{}')::smallint[] AS gaps
FROM finding_scores s
LEFT JOIN finding_score_data_gaps g USING (finding_id, scored_at)
WHERE s.finding_id = @finding_id
GROUP BY s.finding_id, s.scored_at
ORDER BY s.scored_at DESC
LIMIT 1;

-- Stores a Score at the statement's own time, so two Scores of one Finding in
-- one transaction do not share a scored_at.
-- name: InsertFindingScore :one
INSERT INTO finding_scores (
    finding_id, scored_at, model, value, alpha, beta, gamma, vulnerability,
    criticality_multiplier, exposure_multiplier
) VALUES (
    @finding_id, clock_timestamp(), @model, @value, @alpha, @beta, @gamma, @vulnerability,
    @criticality_multiplier, @exposure_multiplier
)
RETURNING scored_at;

-- name: InsertFindingScoreDataGaps :copyfrom
INSERT INTO finding_score_data_gaps (finding_id, scored_at, gap_id) VALUES ($1, $2, $3);
