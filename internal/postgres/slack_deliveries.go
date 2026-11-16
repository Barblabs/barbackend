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
	"github.com/jackc/pgx/v5/pgtype"
)

// NewSlackDelivery is a Slack message the pipeline queues for the worker
// (ADR 0030): its kind, its target and the payload the worker renders.
// Finding is the Finding it is about, uuid.Nil for one about several or
// none (ADR 0033).
type NewSlackDelivery struct {
	Kind       string
	TargetKind string
	Target     string
	Payload    []byte
	Finding    uuid.UUID
}

// EnqueueSlackDeliveries queues the Customer's deliveries, pending and due
// now, to be sent to each target in the order given: rows written in one
// transaction share their created_at, so their ids, time-ordered, keep the
// order the claim follows.
func (t *Tx) EnqueueSlackDeliveries(ctx context.Context, customer tenancy.CustomerID, deliveries []NewSlackDelivery) error {
	rows := make([]sqlcgen.InsertSlackDeliveriesParams, len(deliveries))
	for i, d := range deliveries {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("id of a slack delivery: %w", err)
		}
		rows[i] = sqlcgen.InsertSlackDeliveriesParams{
			ID: id, CustomerID: uuid.UUID(customer), Kind: d.Kind, TargetKind: d.TargetKind, Target: d.Target,
			Payload: d.Payload, FindingID: pgtype.UUID{Bytes: d.Finding, Valid: d.Finding != uuid.Nil},
		}
	}
	if _, err := t.q.InsertSlackDeliveries(ctx, rows); err != nil {
		return fmt.Errorf("enqueue slack deliveries of customer %s: %w", customer, err)
	}
	return nil
}

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

// CustomerSlackDeliveries is how many Slack messages one Customer queued
// were sent, have failed for good and are still pending.
type CustomerSlackDeliveries struct {
	Customer              tenancy.CustomerID
	Name                  string
	Sent, Failed, Pending int
}

// SlackDeliveriesByCustomer counts the Slack messages every Customer queued
// from since on, by name, Customers without any included.
func (t *Tx) SlackDeliveriesByCustomer(ctx context.Context, since time.Time) ([]CustomerSlackDeliveries, error) {
	rows, err := t.q.CountSlackDeliveriesByCustomer(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("count slack deliveries by customer since %s: %w", since, err)
	}
	out := make([]CustomerSlackDeliveries, len(rows))
	for i, row := range rows {
		out[i] = CustomerSlackDeliveries{Customer: tenancy.CustomerID(row.ID), Name: row.Name, Sent: int(row.Sent), Failed: int(row.Failed), Pending: int(row.Pending)}
	}
	return out, nil
}
