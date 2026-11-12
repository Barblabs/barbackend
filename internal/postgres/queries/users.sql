-- name: InsertUser :one
INSERT INTO users (id, cognito_sub, email, customer_id, role_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING created_at;

-- name: InsertUserInvitation :one
INSERT INTO user_invitations (user_id, attempts, next_attempt_at)
VALUES ($1, 1, $2)
RETURNING attempts;

-- name: ClaimDueUserInvitation :one
WITH due AS (
    SELECT i.user_id
    FROM user_invitations i
    JOIN users u ON u.id = i.user_id
    LEFT JOIN customers c ON c.id = u.customer_id
    WHERE i.next_attempt_at <= @now
      AND u.disabled_at IS NULL
      AND c.deactivated_at IS NULL
    ORDER BY i.next_attempt_at
    LIMIT 1
    FOR UPDATE OF i SKIP LOCKED
)
UPDATE user_invitations i
SET attempts = i.attempts + 1, next_attempt_at = @claimed_until
FROM due, users u
WHERE i.user_id = due.user_id AND u.id = i.user_id
RETURNING i.user_id, u.email, i.attempts;

-- name: SetUserSub :execrows
UPDATE users
SET cognito_sub = $2
WHERE id = $1 AND cognito_sub IS NULL;

-- name: DeleteUserInvitation :exec
DELETE FROM user_invitations
WHERE user_id = $1;

-- name: RetryUserInvitation :execrows
UPDATE user_invitations
SET next_attempt_at = $2, last_error = $3
WHERE user_id = $1;

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
WHERE customer_id = $1 AND role_id = $2 AND disabled_at IS NULL AND cognito_sub IS NOT NULL;

-- name: SetUserRole :exec
UPDATE users
SET role_id = $2
WHERE id = $1;

-- name: DisableCustomerUser :execrows
UPDATE users
SET disabled_at = coalesce(disabled_at, now())
WHERE customer_id = $1 AND id = $2;

-- name: GetUserByEmail :one
SELECT sqlc.embed(u), (c.deactivated_at IS NOT NULL)::boolean AS customer_deactivated
FROM users u
LEFT JOIN customers c ON c.id = u.customer_id
WHERE u.email = $1;
