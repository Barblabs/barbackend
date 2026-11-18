package users

import (
	"context"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
)

const (
	DefaultOperationDays = 30
	MaxOperationDays     = 90
)

// ErrInvalidDays is a number of days to look back out of range.
var ErrInvalidDays = errors.New("invalid number of days")

type (
	SyncDay                 = postgres.SyncDay
	CustomerSlackDeliveries = postgres.CustomerSlackDeliveries
)

// SyncHealth is how many Syncs of every Customer's CMDB Source succeeded and
// failed on each of the last days days, in UTC and today included, oldest
// first, for a Platform Admin to watch over the Syncs. A zero days takes
// DefaultOperationDays. It fails with ErrInvalidDays.
func (s *Service) SyncHealth(ctx context.Context, caller tenancy.User, days int) ([]SyncDay, error) {
	if err := caller.ManageCustomers(); err != nil {
		return nil, err
	}
	since, days, err := s.daysBack(days)
	if err != nil {
		return nil, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]SyncDay, error) { return tx.SyncDays(ctx, since, days) })
}

// SlackDeliveries is how many Slack messages each Customer queued in the
// last days days, in UTC and today included, were sent, have failed for good
// and are still pending, by name, for a Platform Admin to watch over the
// alerts. A zero days takes DefaultOperationDays. It fails with
// ErrInvalidDays.
func (s *Service) SlackDeliveries(ctx context.Context, caller tenancy.User, days int) ([]CustomerSlackDeliveries, error) {
	if err := caller.ManageCustomers(); err != nil {
		return nil, err
	}
	since, _, err := s.daysBack(days)
	if err != nil {
		return nil, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]CustomerSlackDeliveries, error) {
		return tx.SlackDeliveriesByCustomer(ctx, since)
	})
}

// daysBack is the midnight, in UTC, that starts the last days days, today
// included, and how many they are.
func (s *Service) daysBack(days int) (time.Time, int, error) {
	if days == 0 {
		days = DefaultOperationDays
	}
	if days < 1 || days > MaxOperationDays {
		return time.Time{}, 0, fmt.Errorf("%w: days must be a number from 1 to %d", ErrInvalidDays, MaxOperationDays)
	}
	now := s.now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day()-(days-1), 0, 0, 0, 0, time.UTC), days, nil
}
