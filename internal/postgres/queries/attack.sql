-- Stores an ATT&CK Technique, or replaces it with a later modification
-- (ADR 0010, ADR 0023).
-- name: UpsertAttackTechnique :exec
INSERT INTO attack_techniques (id, attack_id, name, tactics, revoked, deprecated, object, modified_at)
VALUES (@id, @attack_id, @name, @tactics, @revoked, @deprecated, @object, @modified_at)
ON CONFLICT (id) DO UPDATE
SET attack_id = EXCLUDED.attack_id,
    name = EXCLUDED.name,
    tactics = EXCLUDED.tactics,
    revoked = EXCLUDED.revoked,
    deprecated = EXCLUDED.deprecated,
    object = EXCLUDED.object,
    modified_at = EXCLUDED.modified_at
WHERE attack_techniques.modified_at < EXCLUDED.modified_at;

-- name: UpsertAttackMitigation :exec
INSERT INTO attack_mitigations (id, attack_id, name, object, modified_at)
VALUES (@id, @attack_id, @name, @object, @modified_at)
ON CONFLICT (id) DO UPDATE
SET attack_id = EXCLUDED.attack_id,
    name = EXCLUDED.name,
    object = EXCLUDED.object,
    modified_at = EXCLUDED.modified_at
WHERE attack_mitigations.modified_at < EXCLUDED.modified_at;

-- name: UpsertAttackRelationship :exec
INSERT INTO attack_relationships (id, type, source_id, target_id, description, modified_at)
VALUES (@id, @type, @source_id, @target_id, @description, @modified_at)
ON CONFLICT (id) DO UPDATE
SET type = EXCLUDED.type,
    source_id = EXCLUDED.source_id,
    target_id = EXCLUDED.target_id,
    description = EXCLUDED.description,
    modified_at = EXCLUDED.modified_at
WHERE attack_relationships.modified_at < EXCLUDED.modified_at;

-- name: GetAttackTechnique :one
SELECT id, attack_id, name, tactics, revoked, deprecated, object, modified_at
FROM attack_techniques
WHERE attack_id = @attack_id;

-- The Technique that replaced a revoked one, when it is stored.
-- name: GetRevokingTechnique :one
SELECT t.id, t.attack_id, t.name, t.tactics, t.revoked, t.deprecated, t.object, t.modified_at
FROM attack_relationships r
JOIN attack_techniques t ON t.id = r.target_id
WHERE r.type = 'revoked-by' AND r.source_id = @technique_id
ORDER BY r.modified_at DESC
LIMIT 1;

-- The Mitigations of a Technique, each with its advice for it.
-- name: ListMitigationsOfTechnique :many
SELECT m.attack_id, m.name, r.description
FROM attack_relationships r
JOIN attack_mitigations m ON m.id = r.source_id
WHERE r.type = 'mitigates' AND r.target_id = @technique_id
ORDER BY m.attack_id;
