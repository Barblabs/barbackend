package postgres_test

import (
	"context"
	"testing"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func insertSlackDelivery(t *testing.T, conn *pgx.Conn, customer tenancy.CustomerID, targetKind, target, status string, attempts int, next time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := conn.QueryRow(context.Background(), `
		INSERT INTO slack_deliveries (customer_id, kind, target_kind, target, payload, status, attempts, next_attempt_at, failure_code)
		VALUES ($1, 'finding', $2, $3, '{"cve":"CVE-2026-0001","asset":"web"}', $4, $5, $6, $7)
		RETURNING id`,
		customer, targetKind, target, status, attempts, next, failureCodeOf(status),
	).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func failureCodeOf(status string) *string {
	if status != "failed" {
		return nil
	}
	code := "slack_error"
	return &code
}

func claimDelivery(t *testing.T, db *postgres.DB, now time.Time) (postgres.SlackDelivery, bool) {
	t.Helper()
	claimed, err := postgres.InTxValue(context.Background(), db, func(tx *postgres.Tx) (postgres.SlackDelivery, error) {
		d, _, err := tx.ClaimSlackDelivery(context.Background(), now, now.Add(time.Minute))
		return d, err
	})
	if err != nil {
		t.Fatal(err)
	}
	return claimed, claimed.ID != uuid.Nil
}

func TestClaimSlackDeliveryTakesTheOldestDueRow(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	customer := newCustomer(t, db)
	now := time.Now()
	first := insertSlackDelivery(t, conn, customer, "channel", "C1", "pending", 0, now.Add(-time.Minute))
	second := insertSlackDelivery(t, conn, customer, "channel", "C2", "pending", 0, now)

	got, ok := claimDelivery(t, db, now)
	if !ok || got.ID != first {
		t.Fatalf("claim = %s, %v, want %s", got.ID, ok, first)
	}
	got, ok = claimDelivery(t, db, now)
	if !ok || got.ID != second {
		t.Fatalf("second claim = %s, %v, want %s", got.ID, ok, second)
	}
}

func TestClaimSlackDeliverySkipsRowsNotDue(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	customer := newCustomer(t, db)
	now := time.Now()
	insertSlackDelivery(t, conn, customer, "channel", "C1", "pending", 0, now.Add(time.Minute))

	if _, ok := claimDelivery(t, db, now); ok {
		t.Fatal("claimed a row that is not due")
	}
}

func TestClaimSlackDeliveryKeepsPerTargetOrder(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	customer := newCustomer(t, db)
	now := time.Now()
	first := insertSlackDelivery(t, conn, customer, "channel", "C1", "pending", 0, now.Add(-time.Minute))
	insertSlackDelivery(t, conn, customer, "channel", "C1", "pending", 0, now)
	other := insertSlackDelivery(t, conn, customer, "channel", "C2", "pending", 0, now)

	got, ok := claimDelivery(t, db, now)
	if !ok || got.ID != first {
		t.Fatalf("claim = %s, %v, want %s", got.ID, ok, first)
	}
	// The first row is still pending, so its target's later row waits.
	got, ok = claimDelivery(t, db, now)
	if !ok || got.ID != other {
		t.Fatalf("second claim = %s, %v, want the other target %s", got.ID, ok, other)
	}
	if _, ok := claimDelivery(t, db, now); ok {
		t.Fatal("claimed a later row of a target whose earlier row is pending")
	}
}

func TestDeleteSentSlackDeliveries(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	customer := newCustomer(t, db)
	now := time.Now()
	sent := insertSlackDelivery(t, conn, customer, "channel", "C1", "sent", 1, now)
	pending := insertSlackDelivery(t, conn, customer, "channel", "C2", "pending", 0, now)

	inTx(t, db, func(tx *postgres.Tx) error { return tx.DeleteSentSlackDeliveries(context.Background()) })

	var left []uuid.UUID
	rows, err := conn.Query(context.Background(), "SELECT id FROM slack_deliveries ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		left = append(left, id)
	}
	if len(left) != 1 || left[0] != pending || left[0] == sent {
		t.Fatalf("rows left = %v, want only %s", left, pending)
	}
}

func TestRetryFailedSlackDeliveriesSkipsMalformedPayloads(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	customer := newCustomer(t, db)
	now := time.Now()
	retryable := insertSlackDelivery(t, conn, customer, "channel", "C1", "failed", 3, now)
	malformed := insertSlackDelivery(t, conn, customer, "channel", "C2", "failed", 1, now)
	if _, err := conn.Exec(context.Background(), "UPDATE slack_deliveries SET failure_code = 'malformed_payload' WHERE id = $1", malformed); err != nil {
		t.Fatal(err)
	}

	n, err := postgres.InTxValue(context.Background(), db, func(tx *postgres.Tx) (int64, error) {
		return tx.RetryFailedSlackDeliveries(context.Background(), customer)
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("retried = %d, want 1", n)
	}
	var status string
	var attempts int
	var code *string
	if err := conn.QueryRow(context.Background(), "SELECT status, attempts, failure_code FROM slack_deliveries WHERE id = $1", retryable).Scan(&status, &attempts, &code); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || attempts != 0 || code != nil {
		t.Errorf("retryable row = %s/%d/%v, want pending/0/nil", status, attempts, code)
	}
	if err := conn.QueryRow(context.Background(), "SELECT status FROM slack_deliveries WHERE id = $1", malformed).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Errorf("malformed row = %s, want failed", status)
	}
}
