-- name: InsertUser :exec
INSERT INTO users (id, cognito_sub, email, customer_id, role_id)
VALUES ($1, $2, $3, $4, $5);

-- name: GetUserBySub :one
SELECT u.id, u.email, u.customer_id, u.role_id,
       (u.disabled_at IS NOT NULL)::boolean AS disabled,
       (c.deactivated_at IS NOT NULL)::boolean AS customer_deactivated
FROM users u
LEFT JOIN customers c ON c.id = u.customer_id
WHERE u.cognito_sub = $1;
