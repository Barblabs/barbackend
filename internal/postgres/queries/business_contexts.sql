-- name: GetBusinessContext :one
SELECT b.version, b.schema, b.content, b.saved_at, u.email AS saved_by
FROM business_contexts b
JOIN users u ON u.id = b.saved_by
WHERE b.customer_id = $1
ORDER BY b.version DESC
LIMIT 1;

-- name: NewestBusinessContextVersion :one
SELECT coalesce(max(version), 0)::integer
FROM business_contexts
WHERE customer_id = $1;

-- name: InsertBusinessContext :one
INSERT INTO business_contexts (customer_id, version, schema, content, saved_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING saved_at;
