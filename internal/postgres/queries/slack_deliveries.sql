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
