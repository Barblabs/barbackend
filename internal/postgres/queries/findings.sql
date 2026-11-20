-- The Software Components of Active Assets that have one of the Products,
-- compared in lower case and trimmed, with what scoring needs of their Asset.
-- The two arrays are parallel: element i of each names one Product, already
-- in lower case.
-- name: ListActiveComponentsWithProducts :many
SELECT c.cmdb_source_id, c.record_id, c.position, c.role_id, c.name, c.version,
       c.product_vendor, c.product_name, a.criticality_id,
       coalesce(a.declared_exposure_id, a.imported_exposure_id) AS exposure_id, a.lifecycle_stage_id,
       a.declared_information_classification_id
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
       coalesce(a.declared_exposure_id, a.imported_exposure_id) AS exposure_id, a.lifecycle_stage_id,
       a.declared_information_classification_id
FROM software_components c
JOIN assets a USING (cmdb_source_id, record_id)
WHERE a.inactive_since IS NULL AND c.cmdb_source_id = @cmdb_source_id
ORDER BY c.cmdb_source_id, c.record_id, c.position;

-- Opens, updates or reopens the Finding of one match in one statement, so two
-- matches of the same Finding at once cannot both insert it. previous is read
-- before the statement runs, so it tells what the Finding was: absent (opened),
-- open (updated) or closed (reopened). Times are the transaction's, so
-- first_opened_at <= opened_at holds whatever the application's clock says.
-- A Finding a User closed as false_positive (6), or as accepted_risk (7) or
-- postponed (8) with its reopen_at still ahead, is held: it stays closed and
-- only its component and evidence are updated (ADR 0035). Otherwise the
-- sub-select yields no row, which sets its close to nulls.
-- name: UpsertFinding :one
WITH previous AS (
    SELECT f.closed_at,
           coalesce(f.close_reason_id = 6 OR (f.close_reason_id IN (7, 8) AND f.reopen_at > now()), false) AS held
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
    opened_at         = CASE WHEN findings.closed_at IS NULL OR coalesce((SELECT p.held FROM previous p), false)
                             THEN findings.opened_at ELSE now() END,
    (closed_at, close_reason_id, closed_by, close_note, reopen_at) = (
        SELECT findings.closed_at, findings.close_reason_id, findings.closed_by, findings.close_note, findings.reopen_at
        FROM previous p
        WHERE p.held
    )
RETURNING findings.id,
          (SELECT count(*) FROM previous)::int AS existed,
          coalesce((SELECT bool_or(p.closed_at IS NOT NULL) FROM previous p), false)::boolean AS was_closed,
          (findings.closed_at IS NOT NULL)::boolean AS stays_closed;

-- name: CloseFinding :execrows
UPDATE findings
SET closed_at = now(), close_reason_id = @close_reason_id
WHERE id = @id AND closed_at IS NULL;

-- Closes an open Finding of a Customer's Assets for a reason a User gave
-- (ADR 0035).
-- name: CloseFindingByHand :execrows
UPDATE findings f
SET closed_at = now(), close_reason_id = @close_reason_id,
    closed_by = @closed_by, close_note = @close_note, reopen_at = @reopen_at
FROM cmdb_sources src
WHERE src.id = f.cmdb_source_id AND src.customer_id = @customer_id
  AND f.id = @id AND f.closed_at IS NULL;

-- Whether a Finding of a Customer's Assets is closed, and why.
-- name: GetFindingCloseOfCustomer :one
SELECT f.closed_at, f.close_reason_id
FROM findings f
JOIN cmdb_sources src ON src.id = f.cmdb_source_id
WHERE src.customer_id = @customer_id AND f.id = @id;

-- Reopens a Finding of a Customer's Assets that a User closed (ADR 0035).
-- name: ReopenFindingByHand :execrows
UPDATE findings f
SET opened_at = now(), closed_at = NULL, close_reason_id = NULL,
    closed_by = NULL, close_note = NULL, reopen_at = NULL
FROM cmdb_sources src
WHERE src.id = f.cmdb_source_id AND src.customer_id = @customer_id
  AND f.id = @id AND f.close_reason_id IN (5, 6, 7, 8);

-- The Findings of a Customer's Assets that a User closed, newest close first,
-- with their Asset and who closed them (ADR 0035).
-- name: ListFindingsOfCustomerClosedByHand :many
SELECT f.id, f.cve_id, a.id AS asset_id, a.name AS asset_name,
       f.product_vendor, f.product_name, f.component_name, f.component_version,
       f.close_reason_id::smallint AS close_reason_id, f.closed_at::timestamptz AS closed_at,
       f.close_note::text AS close_note, f.reopen_at, u.email AS closed_by_email
FROM findings f
JOIN cmdb_sources src ON src.id = f.cmdb_source_id
JOIN assets a ON a.cmdb_source_id = f.cmdb_source_id AND a.record_id = f.record_id
JOIN users u ON u.id = f.closed_by
WHERE src.customer_id = @customer_id
ORDER BY f.closed_at DESC, f.id;

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
       coalesce(a.declared_exposure_id, a.imported_exposure_id) AS exposure_id, a.lifecycle_stage_id,
       a.declared_information_classification_id
FROM findings f
JOIN assets a USING (cmdb_source_id, record_id)
WHERE f.cve_id = @cve_id AND f.closed_at IS NULL
ORDER BY f.cmdb_source_id, f.record_id, f.product_vendor, f.product_name;

-- The open Findings of a CMDB Source's Assets, with what scoring needs of
-- their Asset.
-- name: ListOpenFindingsOfSource :many
SELECT f.id, f.cmdb_source_id, f.record_id, f.product_vendor, f.product_name, f.cve_id,
       f.component_name, f.component_version, a.criticality_id,
       coalesce(a.declared_exposure_id, a.imported_exposure_id) AS exposure_id, a.lifecycle_stage_id,
       a.declared_information_classification_id
FROM findings f
JOIN assets a USING (cmdb_source_id, record_id)
WHERE f.closed_at IS NULL AND f.cmdb_source_id = @cmdb_source_id
ORDER BY f.cmdb_source_id, f.record_id, f.product_vendor, f.product_name, f.cve_id;

-- The open Findings of one Asset, with what scoring needs of it.
-- name: ListOpenFindingsOfAsset :many
SELECT f.id, f.cmdb_source_id, f.record_id, f.product_vendor, f.product_name, f.cve_id,
       f.component_name, f.component_version, a.criticality_id,
       coalesce(a.declared_exposure_id, a.imported_exposure_id) AS exposure_id, a.lifecycle_stage_id,
       a.declared_information_classification_id
FROM findings f
JOIN assets a USING (cmdb_source_id, record_id)
WHERE f.cmdb_source_id = @cmdb_source_id AND f.record_id = @record_id AND f.closed_at IS NULL
ORDER BY f.product_vendor, f.product_name, f.cve_id;

-- name: DeleteFindingMatchFlags :exec
DELETE FROM finding_match_flags
WHERE finding_id = @finding_id;

-- name: InsertFindingMatchFlags :copyfrom
INSERT INTO finding_match_flags (finding_id, flag_id) VALUES ($1, $2);

-- The latest Score of a Finding, with its Data Gaps in catalog order.
-- name: LatestFindingScore :one
SELECT s.scored_at, s.model, s.value, s.alpha, s.beta, s.gamma, s.vulnerability,
       s.criticality_multiplier, s.exposure_multiplier, s.lifecycle_multiplier,
       s.exploit_signal, s.information_classification_multiplier,
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
    criticality_multiplier, exposure_multiplier, lifecycle_multiplier,
    exploit_signal, information_classification_multiplier
) VALUES (
    @finding_id, clock_timestamp(), @model, @value, @alpha, @beta, @gamma, @vulnerability,
    @criticality_multiplier, @exposure_multiplier, @lifecycle_multiplier,
    @exploit_signal, @information_classification_multiplier
)
RETURNING scored_at;

-- name: InsertFindingScoreDataGaps :copyfrom
INSERT INTO finding_score_data_gaps (finding_id, scored_at, gap_id) VALUES ($1, $2, $3);

-- The open Findings of a Customer's Assets, with their Vulnerability and their
-- latest Score, which is what their Dossiers are built from (ADR 0026). A
-- Finding not scored yet is left out.
-- name: ListOpenFindingsOfCustomer :many
SELECT f.id, f.cmdb_source_id, f.record_id, f.cve_id, f.component_name, f.component_version,
       v.object AS vulnerability_object,
       s.model, s.value, s.alpha, s.beta, s.gamma, s.vulnerability,
       s.criticality_multiplier, s.exposure_multiplier, s.lifecycle_multiplier,
       s.exploit_signal, s.information_classification_multiplier, s.gaps
FROM findings f
JOIN cmdb_sources src ON src.id = f.cmdb_source_id
JOIN vulnerabilities v ON v.cve_id = f.cve_id
JOIN LATERAL (
    SELECT sc.model, sc.value, sc.alpha, sc.beta, sc.gamma, sc.vulnerability,
           sc.criticality_multiplier, sc.exposure_multiplier, sc.lifecycle_multiplier,
           sc.exploit_signal, sc.information_classification_multiplier,
           coalesce(array_agg(g.gap_id ORDER BY g.gap_id) FILTER (WHERE g.gap_id IS NOT NULL), '{}')::smallint[] AS gaps
    FROM finding_scores sc
    LEFT JOIN finding_score_data_gaps g USING (finding_id, scored_at)
    WHERE sc.finding_id = f.id
    GROUP BY sc.finding_id, sc.scored_at
    ORDER BY sc.scored_at DESC
    LIMIT 1
) s ON true
WHERE src.customer_id = @customer_id AND f.closed_at IS NULL
ORDER BY f.id;

-- One Finding of a Customer's Assets, open or closed, as
-- ListOpenFindingsOfCustomer reads it.
-- name: GetFindingOfCustomer :one
SELECT f.id, f.cmdb_source_id, f.record_id, f.cve_id, f.component_name, f.component_version,
       v.object AS vulnerability_object,
       s.model, s.value, s.alpha, s.beta, s.gamma, s.vulnerability,
       s.criticality_multiplier, s.exposure_multiplier, s.lifecycle_multiplier,
       s.exploit_signal, s.information_classification_multiplier, s.gaps
FROM findings f
JOIN cmdb_sources src ON src.id = f.cmdb_source_id
JOIN vulnerabilities v ON v.cve_id = f.cve_id
JOIN LATERAL (
    SELECT sc.model, sc.value, sc.alpha, sc.beta, sc.gamma, sc.vulnerability,
           sc.criticality_multiplier, sc.exposure_multiplier, sc.lifecycle_multiplier,
           sc.exploit_signal, sc.information_classification_multiplier,
           coalesce(array_agg(g.gap_id ORDER BY g.gap_id) FILTER (WHERE g.gap_id IS NOT NULL), '{}')::smallint[] AS gaps
    FROM finding_scores sc
    LEFT JOIN finding_score_data_gaps g USING (finding_id, scored_at)
    WHERE sc.finding_id = f.id
    GROUP BY sc.finding_id, sc.scored_at
    ORDER BY sc.scored_at DESC
    LIMIT 1
) s ON true
WHERE src.customer_id = @customer_id AND f.id = @id;

-- Every week from the one starting at since to the one starting at
-- last_start, each 168 hours long so no daylight saving change moves it: how
-- many Findings of a Customer's Assets were first opened and how many were
-- closed in it, and how many were open when it ended. A Finding reopened after
-- it was closed counts only its latest close, and counts as open while it was
-- closed before: findings keeps no history.
-- name: CountFindingsOfCustomerByWeek :many
SELECT w.start::timestamptz AS week,
       (SELECT count(*) FROM findings f JOIN cmdb_sources src ON src.id = f.cmdb_source_id
        WHERE src.customer_id = @customer_id
          AND f.first_opened_at >= w.start AND f.first_opened_at < w.start + interval '168 hours')::integer AS opened,
       (SELECT count(*) FROM findings f JOIN cmdb_sources src ON src.id = f.cmdb_source_id
        WHERE src.customer_id = @customer_id
          AND f.closed_at >= w.start AND f.closed_at < w.start + interval '168 hours')::integer AS closed,
       (SELECT count(*) FROM findings f JOIN cmdb_sources src ON src.id = f.cmdb_source_id
        WHERE src.customer_id = @customer_id
          AND f.first_opened_at < w.start + interval '168 hours'
          AND (f.closed_at IS NULL OR f.closed_at >= w.start + interval '168 hours'))::integer AS open_at_end
FROM generate_series(@since::timestamptz, @last_start::timestamptz, interval '168 hours') AS w(start)
ORDER BY w.start;

-- The latest Score of every open Finding of a Customer's Assets, with its
-- Asset, for counting them by Score Band. A Finding not scored yet is left
-- out, as in ListOpenFindingsOfCustomer. Ordered as Assets are listed.
-- name: ListOpenFindingScoresByAssetOfCustomer :many
SELECT a.id AS asset_id, a.name AS asset_name, s.model, s.value
FROM findings f
JOIN cmdb_sources src ON src.id = f.cmdb_source_id
JOIN assets a ON a.cmdb_source_id = f.cmdb_source_id AND a.record_id = f.record_id
JOIN LATERAL (
    SELECT sc.model, sc.value
    FROM finding_scores sc
    WHERE sc.finding_id = f.id
    ORDER BY sc.scored_at DESC
    LIMIT 1
) s ON true
WHERE src.customer_id = @customer_id AND f.closed_at IS NULL
ORDER BY a.name, a.cmdb_source_id, a.record_id;

-- One row per open scored Finding of a Customer's Assets with what the
-- dashboard counts it by: its Asset's Criticality, effective Exposure and
-- Area, its Product and version, its CVE, whether KEV lists it and its EPSS
-- probability, and its latest Score. The extension ids are the kev/1 and
-- epss/1 extension definitions (ADR 0010).
-- name: ListOpenFindingFactsOfCustomer :many
SELECT f.id, a.id AS asset_id, a.criticality_id,
       coalesce(a.declared_exposure_id, a.imported_exposure_id) AS exposure_id,
       ar.id AS area_id, ar.name AS area_name,
       f.product_vendor, f.product_name, f.component_version, f.cve_id,
       ((v.object -> 'extensions' -> @kev_extension_id::text) IS NOT NULL)::boolean AS kev,
       CASE WHEN v.object -> 'extensions' ? @epss_extension_id::text
            THEN (v.object -> 'extensions' -> @epss_extension_id::text ->> 'probability')::double precision END AS epss,
       s.model, s.value
FROM findings f
JOIN cmdb_sources src ON src.id = f.cmdb_source_id
JOIN assets a ON a.cmdb_source_id = f.cmdb_source_id AND a.record_id = f.record_id
LEFT JOIN customer_areas ar ON ar.cmdb_source_id = a.cmdb_source_id AND ar.record_id = a.area_record_id
JOIN vulnerabilities v ON v.cve_id = f.cve_id
JOIN LATERAL (
    SELECT sc.model, sc.value
    FROM finding_scores sc
    WHERE sc.finding_id = f.id
    ORDER BY sc.scored_at DESC
    LIMIT 1
) s ON true
WHERE src.customer_id = @customer_id AND f.closed_at IS NULL
ORDER BY f.id;

-- The Findings of a Customer's Assets closed from since on, with when they
-- were last opened and their latest Score, for how long closing them took. A
-- Finding not scored is left out.
-- name: ListFindingsOfCustomerClosedSince :many
SELECT f.opened_at, f.closed_at, s.model, s.value
FROM findings f
JOIN cmdb_sources src ON src.id = f.cmdb_source_id
JOIN LATERAL (
    SELECT sc.model, sc.value
    FROM finding_scores sc
    WHERE sc.finding_id = f.id
    ORDER BY sc.scored_at DESC
    LIMIT 1
) s ON true
WHERE src.customer_id = @customer_id AND f.closed_at >= @since
ORDER BY f.closed_at;
