package findings

import (
	"context"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
)

const (
	DefaultTrendWeeks = 12
	MaxTrendWeeks     = 52
)

// ErrInvalidTrend is a weekly trend asked for a number of weeks out of range.
var ErrInvalidTrend = errors.New("invalid weekly trend")

type Week = postgres.FindingWeek

// WeeklyTrend is how many of the Customer's Findings were first opened and
// how many were closed in each of the last weeks ISO weeks, in UTC, oldest
// first and the current week last. Every week is there, with zeros when
// nothing happened in it. A zero weeks takes DefaultTrendWeeks. It fails with
// ErrInvalidTrend.
func (s *Service) WeeklyTrend(ctx context.Context, caller tenancy.User, weeks int) ([]Week, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	if weeks == 0 {
		weeks = DefaultTrendWeeks
	}
	if weeks < 1 || weeks > MaxTrendWeeks {
		return nil, fmt.Errorf("%w: weeks must be a number from 1 to %d", ErrInvalidTrend, MaxTrendWeeks)
	}
	since := weekStart(s.now()).AddDate(0, 0, -7*(weeks-1))
	counted, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]Week, error) {
		return tx.FindingWeeksOfCustomer(ctx, customer, since)
	})
	if err != nil {
		return nil, err
	}
	byStart := make(map[int64]Week, len(counted))
	for _, w := range counted {
		byStart[w.Start.Unix()] = w
	}
	trend := make([]Week, weeks)
	for i := range trend {
		start := since.AddDate(0, 0, 7*i)
		trend[i] = byStart[start.Unix()]
		trend[i].Start = start
	}
	return trend, nil
}

// weekStart is the Monday of t's ISO week, at midnight UTC.
func weekStart(t time.Time) time.Time {
	t = t.UTC()
	daysSinceMonday := (int(t.Weekday()) + 6) % 7
	return time.Date(t.Year(), t.Month(), t.Day()-daysSinceMonday, 0, 0, 0, 0, time.UTC)
}
