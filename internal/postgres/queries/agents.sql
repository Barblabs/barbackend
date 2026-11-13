-- name: InsertPrioritization :one
INSERT INTO prioritizations (id, customer_id, previous_id, business_context_version, finding_count, group_count, content)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING created_at;

-- name: InsertFindingPlacements :copyfrom
INSERT INTO finding_placements (id, finding_id, placed_at, dossier)
VALUES ($1, $2, $3, $4);

-- name: InsertPrioritizationFindings :copyfrom
INSERT INTO prioritization_findings (prioritization_id, finding_id, placement_id, group_position, score_rank)
VALUES ($1, $2, $3, $4, $5);

-- name: GetPrioritization :one
SELECT id, previous_id, business_context_version, content, created_at
FROM prioritizations
WHERE id = @id AND customer_id = @customer_id;

-- The newest of a Customer's Prioritizations is the one no other was built
-- from, since they form one chain.
-- name: GetNewestPrioritization :one
SELECT p.id, p.previous_id, p.business_context_version, p.content, p.created_at
FROM prioritizations p
WHERE p.customer_id = @customer_id
  AND NOT EXISTS (SELECT 1 FROM prioritizations n WHERE n.previous_id = p.id);

-- name: ListPrioritizations :many
SELECT id, finding_count, group_count, created_at
FROM prioritizations
WHERE customer_id = @customer_id
ORDER BY created_at DESC, id
LIMIT @page_size;

-- The Findings of a Prioritization with their placements, and when each was
-- closed, null while it is open.
-- name: ListPrioritizationFindings :many
SELECT pf.finding_id, pf.placement_id, fp.placed_at, fp.dossier, f.closed_at
FROM prioritization_findings pf
JOIN prioritizations p ON p.id = pf.prioritization_id
JOIN finding_placements fp ON fp.id = pf.placement_id
JOIN findings f ON f.id = pf.finding_id
WHERE pf.prioritization_id = @prioritization_id AND p.customer_id = @customer_id
ORDER BY pf.group_position, pf.score_rank;

-- name: PrioritizationHolds :one
SELECT EXISTS (
    SELECT 1 FROM prioritization_findings pf
    WHERE pf.prioritization_id = p.id AND pf.finding_id = @finding_id
)::boolean AS holds
FROM prioritizations p
WHERE p.id = @id AND p.customer_id = @customer_id;

-- name: InsertActionPlan :one
INSERT INTO action_plans (id, prioritization_id, finding_id, content)
SELECT @id::uuid, p.id, @finding_id::uuid, @content::jsonb
FROM prioritizations p
WHERE p.id = @prioritization_id AND p.customer_id = @customer_id
RETURNING created_at;

-- The newest Action Plan of each Finding of a Prioritization, whichever
-- Prioritization of the chain it was asked from.
-- name: ListLatestActionPlans :many
SELECT DISTINCT ON (a.finding_id) a.id, a.finding_id, a.content, a.created_at
FROM prioritization_findings pf
JOIN prioritizations p ON p.id = pf.prioritization_id
JOIN action_plans a ON a.finding_id = pf.finding_id
WHERE pf.prioritization_id = @prioritization_id AND p.customer_id = @customer_id
ORDER BY a.finding_id, a.created_at DESC, a.id;

-- name: InsertPrioritizationFeedback :one
INSERT INTO prioritization_feedback (id, prioritization_id, finding_id, author_id, verdict_id, note, via_analista)
SELECT @id::uuid, p.id, @finding_id::uuid, @author_id::uuid, @verdict_id::smallint, @note::text, @via_analista::boolean
FROM prioritizations p
WHERE p.id = @prioritization_id AND p.customer_id = @customer_id
RETURNING created_at;

-- What Users said about the Findings of a Prioritization, whichever
-- Prioritization of the chain they said it on.
-- name: ListPrioritizationFeedback :many
SELECT f.id, f.finding_id, f.author_id, f.verdict_id, f.note, f.via_analista, f.created_at
FROM prioritization_findings pf
JOIN prioritizations p ON p.id = pf.prioritization_id
JOIN prioritization_feedback f ON f.finding_id = pf.finding_id
WHERE pf.prioritization_id = @prioritization_id AND p.customer_id = @customer_id
ORDER BY f.created_at, f.id;

-- name: InsertAnalistaConversation :exec
INSERT INTO analista_conversations (id, customer_id, user_id, history, turns)
VALUES ($1, $2, $3, $4, 1);

-- name: ClaimAnalistaConversation :one
UPDATE analista_conversations
SET answering_since = now()
WHERE id = @id AND customer_id = @customer_id AND user_id = @user_id
  AND (answering_since IS NULL OR answering_since < now() - make_interval(secs => @lifetime_seconds::float8))
RETURNING history, turns;

-- name: AnalistaConversationExists :one
SELECT EXISTS (
    SELECT 1 FROM analista_conversations
    WHERE id = @id AND customer_id = @customer_id AND user_id = @user_id
);

-- name: ReleaseAnalistaConversation :exec
UPDATE analista_conversations
SET answering_since = NULL
WHERE id = @id AND customer_id = @customer_id AND user_id = @user_id AND turns = @turns;

-- name: AdvanceAnalistaConversation :execrows
UPDATE analista_conversations
SET history = @history, turns = turns + 1, answering_since = NULL, updated_at = now()
WHERE id = @id AND customer_id = @customer_id AND user_id = @user_id AND turns = @turns;
