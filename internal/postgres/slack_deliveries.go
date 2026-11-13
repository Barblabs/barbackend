package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SlackDelivery is a queued Slack message the worker is about to send. The
// payload is still the raw jsonb the pipeline wrote (ADR 0030).
type SlackDelivery struct {
	ID         uuid.UUID
	Customer   tenancy.CustomerID
	Kind       string
	TargetKind string
	Target     string
	Payload    []byte
	Attempts   int32
}

// FailedSlackDelivery is a row the worker gave up on, as the portal lists it.
type FailedSlackDelivery struct {
	ID          uuid.UUID
	Kind        string
	TargetKind  string
	Target      string
	Attempts    int32
	FailureCode string
	LastError   string
	CreatedAt   time.Time
}

// DeleteSentSlackDeliveries removes the rows Slack accepted, at the start of
// a poll, so the table only holds pending and failed work.
func (t *Tx) DeleteSentSlackDeliveries(ctx context.Context) error {
	if _, err := t.q.DeleteSentSlackDeliveries(ctx); err != nil {
		return fmt.Errorf("delete sent slack deliveries: %w", err)
	}
	return nil
}

// ClaimSlackDelivery takes the oldest due row, skipping rows another worker
// holds and waiting behind an earlier pending row of the same target. It
// leases the row until claimedUntil and reports false when none is due.
func (t *Tx) ClaimSlackDelivery(ctx context.Context, now, claimedUntil time.Time) (SlackDelivery, bool, error) {
	row, err := t.q.ClaimDueSlackDelivery(ctx, sqlcgen.ClaimDueSlackDeliveryParams{
		Now:          now,
		ClaimedUntil: claimedUntil,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SlackDelivery{}, false, nil
	}
	if err != nil {
		return SlackDelivery{}, false, fmt.Errorf("claim slack delivery: %w", err)
	}
	return SlackDelivery{
		ID:         row.ID,
		Customer:   tenancy.CustomerID(row.CustomerID),
		Kind:       row.Kind,
		TargetKind: row.TargetKind,
		Target:     row.Target,
		Payload:    row.Payload,
		Attempts:   row.Attempts,
	}, true, nil
}

// MarkSlackDeliverySent records that Slack accepted the message; the next
// poll deletes it.
func (t *Tx) MarkSlackDeliverySent(ctx context.Context, id uuid.UUID) error {
	if err := t.q.MarkSlackDeliverySent(ctx, id); err != nil {
		return fmt.Errorf("mark slack delivery %s sent: %w", id, err)
	}
	return nil
}

// FailSlackDelivery gives up on a row, recording why.
func (t *Tx) FailSlackDelivery(ctx context.Context, id uuid.UUID, failureCode, lastError string) error {
	err := t.q.FailSlackDelivery(ctx, sqlcgen.FailSlackDeliveryParams{
		ID:          id,
		FailureCode: &failureCode,
		LastError:   &lastError,
	})
	if err != nil {
		return fmt.Errorf("fail slack delivery %s: %w", id, err)
	}
	return nil
}

// RescheduleSlackDelivery counts one failed attempt and makes the row due
// again at nextAttemptAt.
func (t *Tx) RescheduleSlackDelivery(ctx context.Context, id uuid.UUID, nextAttemptAt time.Time, lastError string) error {
	err := t.q.RescheduleSlackDelivery(ctx, sqlcgen.RescheduleSlackDeliveryParams{
		ID:            id,
		NextAttemptAt: nextAttemptAt,
		LastError:     &lastError,
	})
	if err != nil {
		return fmt.Errorf("reschedule slack delivery %s: %w", id, err)
	}
	return nil
}

// DelaySlackDelivery makes a row due again after Slack's Retry-After,
// counting no failed attempt.
func (t *Tx) DelaySlackDelivery(ctx context.Context, id uuid.UUID, nextAttemptAt time.Time) error {
	err := t.q.DelaySlackDelivery(ctx, sqlcgen.DelaySlackDeliveryParams{
		ID:            id,
		NextAttemptAt: nextAttemptAt,
	})
	if err != nil {
		return fmt.Errorf("delay slack delivery %s: %w", id, err)
	}
	return nil
}

// FailedSlackDeliveries lists a Customer's failed rows, oldest first.
func (t *Tx) FailedSlackDeliveries(ctx context.Context, customer tenancy.CustomerID) ([]FailedSlackDelivery, error) {
	rows, err := t.q.ListFailedSlackDeliveries(ctx, uuid.UUID(customer))
	if err != nil {
		return nil, fmt.Errorf("list failed slack deliveries of customer %s: %w", customer, err)
	}
	failed := make([]FailedSlackDelivery, len(rows))
	for i, row := range rows {
		failed[i] = FailedSlackDelivery{
			ID:          row.ID,
			Kind:        row.Kind,
			TargetKind:  row.TargetKind,
			Target:      row.Target,
			Attempts:    row.Attempts,
			FailureCode: deref(row.FailureCode),
			LastError:   deref(row.LastError),
			CreatedAt:   row.CreatedAt,
		}
	}
	return failed, nil
}

// RetryFailedSlackDeliveries returns a Customer's failed rows to pending,
// except the ones a retry cannot fix. It reports how many it reset.
func (t *Tx) RetryFailedSlackDeliveries(ctx context.Context, customer tenancy.CustomerID) (int64, error) {
	n, err := t.q.RetryFailedSlackDeliveries(ctx, uuid.UUID(customer))
	if err != nil {
		return 0, fmt.Errorf("retry failed slack deliveries of customer %s: %w", customer, err)
	}
	return n, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
