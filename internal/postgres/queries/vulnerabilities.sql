-- Stores a Vulnerability that opened a Finding, or replaces its NVD data.
-- The extensions it already had (kev/1, epss/1) are kept and the new object's
-- extensions win for their own keys, so a Feed never erases another's data
-- (ADR 0010). An older modification never replaces a newer one.
-- name: UpsertVulnerability :exec
INSERT INTO vulnerabilities (cve_id, object, modified_at)
VALUES (@cve_id, @object, @modified_at)
ON CONFLICT (cve_id) DO UPDATE
SET object = jsonb_set(
        EXCLUDED.object, '{extensions}',
        coalesce(vulnerabilities.object -> 'extensions', '{}') || coalesce(EXCLUDED.object -> 'extensions', '{}')),
    modified_at = EXCLUDED.modified_at
WHERE vulnerabilities.modified_at <= EXCLUDED.modified_at;

-- Sets one extension of a stored Vulnerability, such as kev/1 or epss/1. It
-- touches no row when the CVE is not stored, which its caller reads as "no
-- Finding cares about it".
-- name: SetVulnerabilityExtension :execrows
UPDATE vulnerabilities
SET object = jsonb_set(
        jsonb_set(object, '{extensions}', coalesce(object -> 'extensions', '{}')),
        ARRAY['extensions', @extension_id::text], @extension::jsonb)
WHERE cve_id = @cve_id;

-- name: GetVulnerability :one
SELECT cve_id, object, modified_at
FROM vulnerabilities
WHERE cve_id = @cve_id;

-- The stored Vulnerabilities whose nvd/1 affected entries name one of the
-- Products, compared in lower case. The two arrays are parallel: element i of
-- each names one Product, already in lower case.
-- name: ListVulnerabilitiesAffecting :many
SELECT v.cve_id, v.object, v.modified_at
FROM vulnerabilities v
WHERE EXISTS (
    SELECT 1
    FROM jsonb_array_elements(
        CASE jsonb_typeof(v.object -> 'extensions' -> @nvd_extension_id::text -> 'affected')
            WHEN 'array' THEN v.object -> 'extensions' -> @nvd_extension_id::text -> 'affected'
            ELSE '[]'::jsonb
        END) AS entry
    JOIN (
        SELECT vendor.value AS vendor, product.value AS product
        FROM unnest(@vendors::text[]) WITH ORDINALITY AS vendor (value, n)
        JOIN unnest(@products::text[]) WITH ORDINALITY AS product (value, n) USING (n)
    ) AS wanted
      ON lower(entry ->> 'vendor') = wanted.vendor AND lower(entry ->> 'product') = wanted.product
)
ORDER BY v.cve_id;
