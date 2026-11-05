-- name: InsertPrioritization :one
INSERT INTO prioritizations (id, customer_id, finding_count, group_count, content)
VALUES ($1, $2, $3, $4, $5)
RETURNING created_at;

-- name: GetPrioritization :one
SELECT id, content, created_at
FROM prioritizations
WHERE id = @id AND customer_id = @customer_id;

-- name: ListPrioritizations :many
SELECT id, finding_count, group_count, created_at
FROM prioritizations
WHERE customer_id = @customer_id
ORDER BY created_at DESC, id
LIMIT @page_size;

-- name: PrioritizationHolds :one
SELECT (content -> 'findings' @> jsonb_build_array(jsonb_build_object('finding', @finding_id::text)))::boolean AS holds
FROM prioritizations
WHERE id = @id AND customer_id = @customer_id;

-- name: InsertActionPlan :one
INSERT INTO action_plans (id, prioritization_id, finding_id, content)
SELECT @id::uuid, p.id, @finding_id::text, @content::jsonb
FROM prioritizations p
WHERE p.id = @prioritization_id AND p.customer_id = @customer_id
RETURNING created_at;

-- name: ListLatestActionPlans :many
SELECT DISTINCT ON (a.finding_id) a.id, a.finding_id, a.content, a.created_at
FROM action_plans a
JOIN prioritizations p ON p.id = a.prioritization_id
WHERE a.prioritization_id = @prioritization_id AND p.customer_id = @customer_id
ORDER BY a.finding_id, a.created_at DESC, a.id;

-- name: InsertPrioritizationFeedback :one
INSERT INTO prioritization_feedback (id, prioritization_id, finding_id, author_id, verdict_id, note, via_analista)
SELECT @id::uuid, p.id, @finding_id::text, @author_id::uuid, @verdict_id::smallint, @note::text, @via_analista::boolean
FROM prioritizations p
WHERE p.id = @prioritization_id AND p.customer_id = @customer_id
RETURNING created_at;

-- name: ListPrioritizationFeedback :many
SELECT f.id, f.finding_id, f.author_id, f.verdict_id, f.note, f.via_analista, f.created_at
FROM prioritization_feedback f
JOIN prioritizations p ON p.id = f.prioritization_id
WHERE f.prioritization_id = @prioritization_id AND p.customer_id = @customer_id
ORDER BY f.created_at, f.id;
