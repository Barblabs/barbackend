package findings

import (
	"context"
	"fmt"
	"time"

	"barbackend/internal/business"
	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"barbackend/internal/stixext"
	"barbackend/internal/tenancy"
)

// NewsDays is how recently a News Item must have been published for the
// Critical Findings whose CVE it names to be in the news.
const NewsDays = 7

// ServiceStatus is how a Critical Service is doing with the open Findings of
// its Assets.
type ServiceStatus int

const (
	// Clear: none of its open Findings is Critical.
	Clear ServiceStatus = iota + 1
	// Watch: an open Finding is Critical, but none is in KEV or in the news.
	Watch
	// AtRisk: an open Critical Finding is in KEV or in the news.
	AtRisk
)

func (s ServiceStatus) String() string {
	switch s {
	case Clear:
		return "clear"
	case Watch:
		return "watch"
	case AtRisk:
		return "at_risk"
	default:
		return fmt.Sprintf("ServiceStatus(%d)", int(s))
	}
}

// ServiceHealth is how a Critical Service is doing with the open Findings of
// the Active Assets it runs on.
type ServiceHealth struct {
	Name   string
	Status ServiceStatus
	// Open counts the open scored Findings by the Band of their latest Score.
	Open BandCounts
	// InTheNews counts the open Critical Findings whose CVE a News Item
	// published in the last NewsDays names.
	InTheNews int
	// OldestCriticalDays is as in AreaHealth, nil when none is Critical.
	OldestCriticalDays *int
	// UnmatchedAssets are the names of its Assets that match no Active Asset,
	// as the Business Context states them.
	UnmatchedAssets []string
}

// CriticalServiceHealth is the health of each of services, in their order, on
// every Active Asset of the caller's Customer it runs on. A Finding on an
// Asset matched twice counts once.
func (s *Service) CriticalServiceHealth(ctx context.Context, caller tenancy.User, services []business.CriticalService) ([]ServiceHealth, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	out := make([]ServiceHealth, 0, len(services))
	if len(services) == 0 {
		return out, nil
	}
	now := s.now()
	read, err := s.readServiceHealth(ctx, customer, now.Add(-NewsDays*24*time.Hour))
	if err != nil {
		return nil, err
	}
	for _, svc := range services {
		out = append(out, read.health(svc, now))
	}
	return out, nil
}

type serviceHealthReads struct {
	names  []string
	facts  []postgres.FindingAssetFact
	scores map[finding.ID][]postgres.TimedScore
}

func (s *Service) readServiceHealth(ctx context.Context, customer tenancy.CustomerID, newsSince time.Time) (serviceHealthReads, error) {
	var r serviceHealthReads
	err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		var err error
		if r.names, err = tx.ActiveAssetNamesOfCustomer(ctx, customer); err != nil {
			return err
		}
		if r.facts, err = tx.OpenFindingAssetFactsOfCustomer(ctx, customer, string(stixext.KEVDefinitionID), newsSince); err != nil {
			return err
		}
		var critical []finding.ID
		for _, f := range r.facts {
			if isCritical(f.Score) {
				critical = append(critical, f.ID)
			}
		}
		r.scores, err = tx.ScoresOf(ctx, critical)
		return err
	})
	return r, err
}

func (r serviceHealthReads) health(svc business.CriticalService, now time.Time) ServiceHealth {
	h := ServiceHealth{Name: svc.Name, Status: Clear, UnmatchedAssets: svc.UnmatchedAssets(r.names)}
	for _, f := range r.facts {
		if svc.RunsOn(f.AssetName) {
			h.add(f, r.scores[f.ID], now)
		}
	}
	return h
}

func (h *ServiceHealth) add(f postgres.FindingAssetFact, history []postgres.TimedScore, now time.Time) {
	if f.Score.Model == 0 {
		return
	}
	h.Open.Add(f.Score)
	if !isCritical(f.Score) {
		return
	}
	if days := criticalDays(history, now); h.OldestCriticalDays == nil || days > *h.OldestCriticalDays {
		h.OldestCriticalDays = &days
	}
	if f.InTheNews {
		h.InTheNews++
	}
	switch {
	case f.KEV || f.InTheNews:
		h.Status = AtRisk
	case h.Status == Clear:
		h.Status = Watch
	}
}

func isCritical(s scoring.Score) bool {
	band, ok := s.Band()
	return ok && band == scoring.BandCritical
}
