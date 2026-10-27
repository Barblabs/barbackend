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

-- name: SetCustomerDeactivated :one
UPDATE customers
SET deactivated_at = CASE WHEN @deactivated::boolean THEN coalesce(deactivated_at, now()) END
WHERE id = @id
RETURNING id, name, created_at, deactivated_at;
