package findings

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"barbackend/internal/tenancy"
)

const (
	DefaultClosesDays = 30
	MaxClosesDays     = 365
)

// ErrInvalidCloses is a count of closes asked for a number of days out of
// range.
var ErrInvalidCloses = errors.New("invalid closes count")

// CloseBucket is how the Summary counts a close: Fixed, Went away or Set
// aside, never added together.
type CloseBucket int

const (
	// Fixed: someone's work removed the vulnerable component or version.
	Fixed CloseBucket = iota + 1
	// WentAway: the Finding stopped applying with no one fixing it.
	WentAway
	// SetAside: a User chose not to attend it now.
	SetAside
)

// BucketOf is the CloseBucket of a close for r, or 0 for a reason it does not
// know.
func BucketOf(r finding.CloseReason) CloseBucket {
	switch r {
	case finding.Remediated, finding.ComponentRemoved, finding.NoLongerAffected:
		return Fixed
	case finding.AssetInactive, finding.VulnerabilityRejected, finding.VulnerabilityRevised:
		return WentAway
	case finding.AcceptedRisk, finding.Postponed, finding.FalsePositive:
		return SetAside
	default:
		return 0
	}
}

// CloseCounts is how many Findings were first opened in a window and how many
// were closed in it, by CloseBucket.
type CloseCounts struct {
	Opened, Fixed, WentAway, SetAside int
}

func (c *CloseCounts) addClose(r finding.CloseReason) {
	switch BucketOf(r) {
	case Fixed:
		c.Fixed++
	case WentAway:
		c.WentAway++
	case SetAside:
		c.SetAside++
	}
}

// Closes counts a Customer's Findings in the last days ending now and in the
// days before that.
type Closes struct {
	Current, Previous CloseCounts
	// CriticalFixedMedianDays is the median days from opening to closing of
	// the Fixed Findings of Current whose latest Score is Critical, nil when
	// there are none.
	CriticalFixedMedianDays *float64
}

// Closes counts the Customer's Findings first opened and closed, by
// CloseBucket, in the last days days ending now and in the days days before
// that. A Finding closed and then reopened is not counted as closed, since it
// keeps only its latest close. A zero days takes DefaultClosesDays. It fails
// with ErrInvalidCloses.
func (s *Service) Closes(ctx context.Context, caller tenancy.User, days int) (Closes, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return Closes{}, err
	}
	if days == 0 {
		days = DefaultClosesDays
	}
	if days < 1 || days > MaxClosesDays {
		return Closes{}, fmt.Errorf("%w: days must be a number from 1 to %d", ErrInvalidCloses, MaxClosesDays)
	}
	window := time.Duration(days) * 24 * time.Hour
	start := s.now().Add(-window)
	previousStart := start.Add(-window)
	var closes []postgres.FindingCloseFact
	var opens []time.Time
	if err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		if closes, err = tx.FindingCloseFactsOfCustomer(ctx, customer, previousStart); err != nil {
			return err
		}
		opens, err = tx.FirstOpensOfCustomer(ctx, customer, previousStart)
		return err
	}); err != nil {
		return Closes{}, err
	}
	var c Closes
	for _, opened := range opens {
		c.in(opened, start).Opened++
	}
	var criticalFixedDays []float64
	for _, f := range closes {
		c.in(f.ClosedAt, start).addClose(f.Reason)
		if band, _ := f.Score.Band(); !f.ClosedAt.Before(start) && BucketOf(f.Reason) == Fixed && band == scoring.BandCritical {
			criticalFixedDays = append(criticalFixedDays, f.ClosedAt.Sub(f.OpenedAt).Hours()/24)
		}
	}
	c.CriticalFixedMedianDays = median(criticalFixedDays)
	return c, nil
}

func (c *Closes) in(t, start time.Time) *CloseCounts {
	if t.Before(start) {
		return &c.Previous
	}
	return &c.Current
}

func median(values []float64) *float64 {
	if len(values) == 0 {
		return nil
	}
	slices.Sort(values)
	m := values[len(values)/2]
	if len(values)%2 == 0 {
		m = (values[len(values)/2-1] + m) / 2
	}
	return &m
}
