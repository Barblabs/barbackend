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
// how many were closed in each of the last weeks ISO weeks, in UTC, and how
// many were open when each ended, oldest first and the current week last.
// Every week is there, with zeros when nothing happened in it. A zero weeks
// takes DefaultTrendWeeks. It fails with ErrInvalidTrend.
func (s *Service) WeeklyTrend(ctx context.Context, caller tenancy.User, weeks int) ([]Week, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	since, weeks, err := s.window(weeks)
	if err != nil {
		return nil, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]Week, error) {
		return tx.FindingWeeksOfCustomer(ctx, customer, since, weeks)
	})
}

// window is when the last weeks ISO weeks start, the current one included,
// and how many they are: DefaultTrendWeeks for a zero weeks. It fails with
// ErrInvalidTrend.
func (s *Service) window(weeks int) (time.Time, int, error) {
	if weeks == 0 {
		weeks = DefaultTrendWeeks
	}
	if weeks < 1 || weeks > MaxTrendWeeks {
		return time.Time{}, 0, fmt.Errorf("%w: weeks must be a number from 1 to %d", ErrInvalidTrend, MaxTrendWeeks)
	}
	return weekStart(s.now()).AddDate(0, 0, -7*(weeks-1)), weeks, nil
}

// weekStart is the Monday of t's ISO week, at midnight UTC.
func weekStart(t time.Time) time.Time {
	t = t.UTC()
	daysSinceMonday := (int(t.Weekday()) + 6) % 7
	return time.Date(t.Year(), t.Month(), t.Day()-daysSinceMonday, 0, 0, 0, 0, time.UTC)
}
