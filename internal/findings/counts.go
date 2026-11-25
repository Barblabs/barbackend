package findings

import (
	"cmp"
	"context"
	"errors"
	"fmt"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"barbackend/internal/stixext"
	"barbackend/internal/tenancy"
)

const (
	DefaultTopLimit = 10
	MaxTopLimit     = 50
)

// ErrInvalidCount is a count of Findings asked for with a limit or a role it
// does not have.
var ErrInvalidCount = errors.New("invalid finding count")

// BandCounts counts open Findings by the Score Band of their latest Score.
type BandCounts = scoring.BandCounts

func moreSevere(a, b BandCounts) int {
	return cmp.Or(
		cmp.Compare(b.Critical, a.Critical), cmp.Compare(b.High, a.High),
		cmp.Compare(b.Medium, a.Medium), cmp.Compare(b.Low, a.Low),
	)
}

// Summary is the Customer's open scored Findings at a glance.
type Summary struct {
	Bands BandCounts
	// KEV counts those whose CVE KEV lists.
	KEV int
	// CriticalInternetFacing counts the Critical ones on Internet-facing
	// Assets, the most urgent.
	CriticalInternetFacing int
}

// Summary counts the Customer's open scored Findings by Score Band, and how
// many of them KEV lists and are Critical on Internet-facing Assets.
func (s *Service) Summary(ctx context.Context, caller tenancy.User) (Summary, error) {
	facts, err := s.openFacts(ctx, caller)
	if err != nil {
		return Summary{}, err
	}
	var sum Summary
	for _, f := range facts {
		sum.Bands.Add(f.Score)
		if f.KEV {
			sum.KEV++
		}
		if band, _ := f.Score.Band(); band == scoring.BandCritical && f.Exposure == inventory.InternetFacing {
			sum.CriticalInternetFacing++
		}
	}
	return sum, nil
}

// topLimit is limit, or DefaultTopLimit for zero. It fails with
// ErrInvalidCount out of range.
func topLimit(limit int) (int, error) {
	if limit == 0 {
		return DefaultTopLimit, nil
	}
	if limit < 1 || limit > MaxTopLimit {
		return 0, fmt.Errorf("%w: limit must be a number from 1 to %d", ErrInvalidCount, MaxTopLimit)
	}
	return limit, nil
}

func (s *Service) openFacts(ctx context.Context, caller tenancy.User) ([]postgres.OpenFindingFact, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]postgres.OpenFindingFact, error) {
		return tx.OpenFindingFactsOfCustomer(ctx, customer, string(stixext.KEVDefinitionID), string(stixext.EPSSDefinitionID))
	})
}
