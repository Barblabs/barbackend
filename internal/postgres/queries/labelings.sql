-- The stored Vulnerabilities the Cartógrafo should label (ADR 0024): those
-- with no Labeling, and those whose Labeling failed with attempts left,
-- newest first.
-- name: ListUnlabeledVulnerabilities :many
SELECT v.cve_id
FROM vulnerabilities v
LEFT JOIN vulnerability_labelings l ON l.cve_id = v.cve_id
WHERE l.cve_id IS NULL
   OR (l.outcome = 'failed' AND l.attempts < @max_attempts::integer)
ORDER BY v.stored_at DESC, v.cve_id
LIMIT @max_vulnerabilities::integer;

-- Records an attempt to label a Vulnerability. A labeled or none Labeling is
-- final and is left as it is, so no row is touched; a failed one counts one
-- more attempt.
-- name: RecordLabeling :execrows
INSERT INTO vulnerability_labelings (cve_id, outcome, attempts, model, prompt_hash)
VALUES (@cve_id, @outcome, 1, @model, @prompt_hash)
ON CONFLICT (cve_id) DO UPDATE
SET outcome = EXCLUDED.outcome,
    attempts = vulnerability_labelings.attempts + 1,
    model = EXCLUDED.model,
    prompt_hash = EXCLUDED.prompt_hash,
    labeled_at = now()
WHERE vulnerability_labelings.outcome = 'failed';

-- name: InsertVulnerabilityTechnique :exec
INSERT INTO vulnerability_techniques (cve_id, attack_id, role, evidence, rationale)
VALUES (@cve_id, @attack_id, @role, @evidence, @rationale);

-- name: GetVulnerabilityLabeling :one
SELECT cve_id, outcome, attempts, model, prompt_hash, labeled_at
FROM vulnerability_labelings
WHERE cve_id = @cve_id;

-- The Techniques of a Vulnerability, how it is exploited first and what
-- follows after.
-- name: ListTechniquesOfVulnerability :many
SELECT attack_id, role, evidence, rationale
FROM vulnerability_techniques
WHERE cve_id = @cve_id
ORDER BY array_position(ARRAY['exploitation', 'primary_impact', 'secondary_impact'], role), attack_id;

-- How many Labelings were attempted since a moment, so the Cartógrafo's
-- daily cap holds across restarts of serve (ADR 0024). A Labeling counts once,
-- at its last attempt.
-- name: CountLabelingsSince :one
SELECT count(*)::integer
FROM vulnerability_labelings
WHERE labeled_at >= @since;
