-- Stores an Advisory, or replaces it when its Feed published it again
-- (ADR 0022).
-- name: UpsertAdvisory :exec
INSERT INTO advisories (id, feed, published_at, object, modified_at)
VALUES (@id, @feed, @published_at, @object, @modified_at)
ON CONFLICT (id) DO UPDATE
SET feed = EXCLUDED.feed,
    published_at = EXCLUDED.published_at,
    object = EXCLUDED.object,
    modified_at = EXCLUDED.modified_at;

-- Links an Advisory to the stored Vulnerabilities of those CVEs. A link
-- already there is kept as it is, and none is ever removed.
-- name: LinkAdvisory :exec
INSERT INTO vulnerability_advisories (cve_id, advisory_id)
SELECT cve_id, @advisory_id
FROM unnest(@cve_ids::text[]) AS cve_id
ON CONFLICT (cve_id, advisory_id) DO NOTHING;

-- The Advisories of a stored Vulnerability, newest first.
-- name: ListAdvisoriesOfVulnerability :many
SELECT a.id, a.feed, a.published_at, a.object, a.modified_at
FROM vulnerability_advisories va
JOIN advisories a ON a.id = va.advisory_id
WHERE va.cve_id = @cve_id
ORDER BY a.published_at DESC, a.id;

-- The Advisories of some stored Vulnerabilities, each newest first.
-- name: ListAdvisoriesOfVulnerabilities :many
SELECT va.cve_id, a.id, a.feed, a.published_at, a.object, a.modified_at
FROM vulnerability_advisories va
JOIN advisories a ON a.id = va.advisory_id
WHERE va.cve_id = ANY(@cve_ids::text[])
ORDER BY va.cve_id, a.published_at DESC, a.id;
