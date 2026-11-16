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

-- What a Platform Admin sees of every Customer: how many enabled Users it
-- has and how its connected CMDB Source last synced, never its Assets or
-- Findings (ADR 0013).
-- name: ListCustomerStats :many
SELECT c.id, c.name, c.created_at, c.deactivated_at,
       (SELECT count(*) FROM users u WHERE u.customer_id = c.id AND u.disabled_at IS NULL)::integer AS user_count,
       (src.id IS NOT NULL)::boolean AS cmdb_connected,
       latest.outcome_id AS latest_sync_outcome_id,
       latest.finished_at AS latest_sync_finished_at,
       succeeded.finished_at AS last_succeeded_sync_finished_at
FROM customers c
LEFT JOIN cmdb_sources src ON src.customer_id = c.id AND src.disconnected_at IS NULL
LEFT JOIN sync_runs latest ON latest.cmdb_source_id = src.id
    AND NOT EXISTS (
        SELECT 1
        FROM sync_runs newer
        WHERE newer.cmdb_source_id = src.id AND (newer.started_at, newer.id) > (latest.started_at, latest.id)
    )
LEFT JOIN sync_runs succeeded ON succeeded.cmdb_source_id = src.id AND succeeded.outcome_id = @succeeded_outcome_id
    AND NOT EXISTS (
        SELECT 1
        FROM sync_runs newer
        WHERE newer.cmdb_source_id = src.id AND newer.outcome_id = @succeeded_outcome_id
          AND (newer.started_at, newer.id) > (succeeded.started_at, succeeded.id)
    )
ORDER BY lower(c.name);

-- name: GetCustomer :one
SELECT id, name, created_at, deactivated_at
FROM customers
WHERE id = $1;
