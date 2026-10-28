-- name: InsertCustomer :one
INSERT INTO customers (id, name)
VALUES ($1, $2)
RETURNING created_at;

-- name: ListCustomers :many
SELECT id, name, created_at, deactivated_at
FROM customers
ORDER BY lower(name);

-- name: RenameCustomer :one
UPDATE customers
SET name = $2
WHERE id = $1
RETURNING id, name, created_at, deactivated_at;

-- name: DeactivateCustomer :one
UPDATE customers
SET deactivated_at = coalesce(deactivated_at, now())
WHERE id = $1
RETURNING id, name, created_at, deactivated_at;

-- name: ReactivateCustomer :one
UPDATE customers
SET deactivated_at = NULL
WHERE id = $1
RETURNING id, name, created_at, deactivated_at;

-- name: GetCustomer :one
SELECT id, name, created_at, deactivated_at
FROM customers
WHERE id = $1;
