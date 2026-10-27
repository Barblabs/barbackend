-- name: InsertUser :one
INSERT INTO users (id, cognito_sub, email, customer_id, role_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING created_at;

-- name: GetUserBySub :one
SELECT sqlc.embed(u), (c.deactivated_at IS NOT NULL)::boolean AS customer_deactivated
FROM users u
LEFT JOIN customers c ON c.id = u.customer_id
WHERE u.cognito_sub = $1;

-- name: ListCustomerUsers :many
SELECT sqlc.embed(u), (c.deactivated_at IS NOT NULL)::boolean AS customer_deactivated
FROM users u
JOIN customers c ON c.id = u.customer_id
WHERE u.customer_id = $1
ORDER BY u.email;

-- name: GetCustomerUser :one
SELECT sqlc.embed(u), (c.deactivated_at IS NOT NULL)::boolean AS customer_deactivated
FROM users u
JOIN customers c ON c.id = u.customer_id
WHERE u.customer_id = $1 AND u.id = $2;

-- name: LockCustomer :exec
SELECT id FROM customers WHERE id = $1 FOR UPDATE;

-- name: CountActiveUsersWithRole :one
SELECT count(*)
FROM users
WHERE customer_id = $1 AND role_id = $2 AND disabled_at IS NULL;

-- name: SetUserRole :exec
UPDATE users
SET role_id = $2
WHERE id = $1;

-- name: DisableCustomerUser :execrows
UPDATE users
SET disabled_at = coalesce(disabled_at, now())
WHERE customer_id = $1 AND id = $2;
