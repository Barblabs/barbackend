-- name: DeleteSentSlackDeliveries :execrows
DELETE FROM slack_deliveries
WHERE status = 'sent';

-- name: ClaimDueSlackDelivery :one
WITH due AS (
    SELECT d.id
    FROM slack_deliveries d
    WHERE d.status = 'pending'
      AND d.next_attempt_at <= @now
      -- Per-target FIFO: a later message waits behind an earlier one that is
      -- still pending, even while that one is leased or backing off.
      AND NOT EXISTS (
          SELECT 1
          FROM slack_deliveries earlier
          WHERE earlier.customer_id = d.customer_id
            AND earlier.target = d.target
            AND earlier.status = 'pending'
            AND (earlier.created_at, earlier.id) < (d.created_at, d.id)
      )
    ORDER BY d.next_attempt_at, d.created_at, d.id
    LIMIT 1
    FOR UPDATE OF d SKIP LOCKED
)
UPDATE slack_deliveries d
SET next_attempt_at = @claimed_until
FROM due
WHERE d.id = due.id
RETURNING d.id, d.customer_id, d.kind, d.target_kind, d.target, d.payload, d.attempts;

-- name: MarkSlackDeliverySent :exec
UPDATE slack_deliveries
SET status = 'sent'
WHERE id = @id;

-- name: FailSlackDelivery :exec
UPDATE slack_deliveries
SET status = 'failed',
    attempts = attempts + 1,
    failure_code = @failure_code,
    last_error = @last_error
WHERE id = @id;

-- name: RescheduleSlackDelivery :exec
UPDATE slack_deliveries
SET attempts = attempts + 1,
    next_attempt_at = @next_attempt_at,
    last_error = @last_error
WHERE id = @id;

-- name: DelaySlackDelivery :exec
UPDATE slack_deliveries
SET next_attempt_at = @next_attempt_at
WHERE id = @id;

-- name: ListFailedSlackDeliveries :many
SELECT id, kind, target_kind, target, attempts, failure_code, last_error, created_at
FROM slack_deliveries
WHERE customer_id = @customer_id AND status = 'failed'
ORDER BY created_at, id;

-- name: RetryFailedSlackDeliveries :execrows
UPDATE slack_deliveries
SET status = 'pending',
    attempts = 0,
    failure_code = NULL,
    last_error = NULL,
    next_attempt_at = now()
WHERE customer_id = @customer_id
  AND status = 'failed'
  AND failure_code IS DISTINCT FROM 'malformed_payload';

-- name: InsertSlackDeliveries :copyfrom
INSERT INTO slack_deliveries (id, customer_id, kind, target_kind, target, payload, finding_id)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- How many Slack messages each Customer queued from since on were sent, have
-- failed for good and are still pending, every Customer included, by name.
-- name: CountSlackDeliveriesByCustomer :many
SELECT c.id, c.name,
       (count(d.id) FILTER (WHERE d.status = 'sent'))::integer AS sent,
       (count(d.id) FILTER (WHERE d.status = 'failed'))::integer AS failed,
       (count(d.id) FILTER (WHERE d.status = 'pending'))::integer AS pending
FROM customers c
LEFT JOIN slack_deliveries d ON d.customer_id = c.id AND d.created_at >= @since
GROUP BY c.id, c.name
ORDER BY lower(c.name);
