-- name: InsertUser :one
INSERT INTO users (id, cognito_sub, email, customer_id, role_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING created_at;

-- name: GetUserBySub :one
SELECT u.id, u.email, u.customer_id, u.role_id,
       (u.disabled_at IS NOT NULL)::boolean AS disabled,
       (c.deactivated_at IS NOT NULL)::boolean AS customer_deactivated
FROM users u
LEFT JOIN customers c ON c.id = u.customer_id
WHERE u.cognito_sub = $1;

-- name: ListCustomerUsers :many
SELECT id, cognito_sub, email, customer_id, role_id, created_at, disabled_at
FROM users
WHERE customer_id = $1
ORDER BY email;

-- name: LockCustomer :exec
SELECT id FROM customers WHERE id = $1 FOR UPDATE;

-- name: GetCustomerUser :one
SELECT id, cognito_sub, email, customer_id, role_id, created_at, disabled_at
FROM users
WHERE customer_id = $1 AND id = $2;

-- name: CountActiveUsersWithRole :one
SELECT count(*)
FROM users
WHERE customer_id = $1 AND role_id = $2 AND disabled_at IS NULL;

-- name: SetUserRole :one
UPDATE users
SET role_id = $2
WHERE id = $1
RETURNING id, cognito_sub, email, customer_id, role_id, created_at, disabled_at;

-- name: DisableUser :one
UPDATE users
SET disabled_at = coalesce(disabled_at, now())
WHERE id = $1
RETURNING id, cognito_sub, email, customer_id, role_id, created_at, disabled_at;
