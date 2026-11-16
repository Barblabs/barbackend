package findings

import (
	"context"
	"slices"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"barbackend/internal/tenancy"
)

// CloseTime is how long closing some Findings took, from when each was last
// opened. Median and Average are zero when none was closed.
type CloseTime struct {
	Closed          int
	Median, Average time.Duration
}

// TimesToClose is how long closing a Customer's Findings took, by the Score
// Band of their latest Score.
type TimesToClose struct {
	Critical, High, Medium, Low CloseTime
	// Unbanded is the Findings whose latest Score is from a Scoring Model
	// without Bands.
	Unbanded CloseTime
}

// TimeToClose is how long closing the Customer's scored Findings closed in
// the last weeks ISO weeks took, in UTC and the current week included, by
// Score Band. A reopened Finding counts from when it was last opened. A zero
// weeks takes DefaultTrendWeeks. It fails with ErrInvalidTrend.
func (s *Service) TimeToClose(ctx context.Context, caller tenancy.User, weeks int) (TimesToClose, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return TimesToClose{}, err
	}
	since, _, err := s.window(weeks)
	if err != nil {
		return TimesToClose{}, err
	}
	closed, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]postgres.ClosedFinding, error) {
		return tx.FindingsOfCustomerClosedSince(ctx, customer, since)
	})
	if err != nil {
		return TimesToClose{}, err
	}
	var critical, high, medium, low, unbanded []time.Duration
	for _, c := range closed {
		took := c.Closed.Sub(c.Opened)
		switch {
		case !c.Banded:
			unbanded = append(unbanded, took)
		case c.Band == scoring.BandCritical:
			critical = append(critical, took)
		case c.Band == scoring.BandHigh:
			high = append(high, took)
		case c.Band == scoring.BandMedium:
			medium = append(medium, took)
		default:
			low = append(low, took)
		}
	}
	return TimesToClose{
		Critical: closeTime(critical), High: closeTime(high), Medium: closeTime(medium), Low: closeTime(low), Unbanded: closeTime(unbanded),
	}, nil
}

func closeTime(took []time.Duration) CloseTime {
	if len(took) == 0 {
		return CloseTime{}
	}
	slices.Sort(took)
	var sum time.Duration
	for _, d := range took {
		sum += d
	}
	median := took[len(took)/2]
	if len(took)%2 == 0 {
		median = (took[len(took)/2-1] + took[len(took)/2]) / 2
	}
	return CloseTime{Closed: len(took), Median: median, Average: sum / time.Duration(len(took))}
}
