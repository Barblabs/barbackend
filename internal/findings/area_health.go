package findings

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"barbackend/internal/tenancy"
)

const (
	// AgingCriticalDays is how long an open Finding may stay Critical before
	// its Area needs help.
	AgingCriticalDays = 30
	// GrowingWeeks is how many complete ISO weeks in a row an Area must open
	// more Findings than it closes before it needs help.
	GrowingWeeks = 3
	// AreaHealthDays is the window of Fixed and of the backlog's change.
	AreaHealthDays = 30
)

// HealthReason is why an Area needs help.
type HealthReason int

const (
	// AgingCritical: an open Finding has been Critical over
	// AgingCriticalDays.
	AgingCritical HealthReason = iota + 1
	// Growing: each of the last GrowingWeeks complete ISO weeks first opened
	// more Findings than it closed.
	Growing
)

func (r HealthReason) String() string {
	switch r {
	case AgingCritical:
		return "aging_critical"
	case Growing:
		return "growing"
	default:
		return fmt.Sprintf("HealthReason(%d)", int(r))
	}
}

// AreaHealth is how an Active Area, or the Assets with no Area, are doing
// with their Findings.
type AreaHealth struct {
	// ID is nil for the Assets with no Area; Name and OwnerEmail are then
	// empty and nil.
	ID         *int64
	Name       string
	OwnerEmail *string
	// AssetCount counts its Active Assets.
	AssetCount int
	// Open counts its open scored Findings by the Band of their latest Score.
	Open BandCounts
	// OldestCriticalDays is the whole days since the longest-Critical open
	// Finding's latest unbroken run of Critical Scores began, nil when none
	// is Critical.
	OldestCriticalDays *int
	// Fixed counts its Findings closed as Fixed in the last AreaHealthDays.
	Fixed int
	// Open30DaysAgo counts all its Findings open AreaHealthDays ago.
	Open30DaysAgo int
	Reasons       []HealthReason
}

// NeedsHelp is whether it has any HealthReason.
func (a AreaHealth) NeedsHelp() bool { return len(a.Reasons) > 0 }

type areaTally struct {
	health         AreaHealth
	opened, closed [GrowingWeeks]int
}

// AreaHealth is the health of each of the Customer's Active Areas, and of its
// Assets with no Area when they have open Findings: flagged first, then the
// oldest Critical first, with none last, then the most Critical open, then by
// name, with no Area last. A Finding whose Asset is in an Inactive Area is left out. A Finding
// closed and then reopened keeps only its latest close.
func (s *Service) AreaHealth(ctx context.Context, caller tenancy.User) ([]AreaHealth, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	now := s.now()
	windowStart := now.Add(-AreaHealthDays * 24 * time.Hour)
	thisWeek := weekStart(now)
	since := thisWeek.AddDate(0, 0, -7*GrowingWeeks)
	if windowStart.Before(since) {
		since = windowStart
	}
	read, err := s.readAreaHealth(ctx, customer, since)
	if err != nil {
		return nil, err
	}

	tallies := make(map[int64]*areaTally, len(read.areas))
	order := make([]*areaTally, 0, len(read.areas)+1)
	for _, a := range read.areas {
		t := &areaTally{health: AreaHealth{ID: &a.ID, Name: a.Name, OwnerEmail: a.OwnerEmail, AssetCount: a.AssetCount}}
		tallies[a.ID] = t
		order = append(order, t)
	}
	none := &areaTally{health: AreaHealth{AssetCount: read.withoutArea}}
	for _, f := range read.facts {
		t := none
		if f.AreaID != nil {
			if t = tallies[*f.AreaID]; t == nil {
				continue
			}
		}
		t.addOpen(f, read.scores[f.ID], now)
		t.addWindow(f, windowStart)
		t.addWeeks(f, thisWeek)
	}
	if none.health.Open.Total() > 0 {
		order = append(order, none)
	}

	out := make([]AreaHealth, len(order))
	for i, t := range order {
		out[i] = t.result()
	}
	slices.SortStableFunc(out, compareAreaHealth)
	return out, nil
}

func compareAreaHealth(a, b AreaHealth) int {
	return cmp.Or(
		compareFlagged(a, b),
		compareOldestCritical(a, b),
		cmp.Compare(b.Open.Critical, a.Open.Critical),
		compareName(a, b),
	)
}

func compareName(a, b AreaHealth) int {
	switch {
	case (a.ID == nil) != (b.ID == nil) && a.ID == nil:
		return 1
	case (a.ID == nil) != (b.ID == nil):
		return -1
	default:
		return strings.Compare(a.Name, b.Name)
	}
}

type areaHealthReads struct {
	areas       []postgres.AreaAssets
	withoutArea int
	facts       []postgres.FindingAreaFact
	scores      map[finding.ID][]postgres.TimedScore
}

func (s *Service) readAreaHealth(ctx context.Context, customer tenancy.CustomerID, since time.Time) (areaHealthReads, error) {
	var r areaHealthReads
	err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		var err error
		if r.areas, err = tx.ActiveAreaAssetsOfCustomer(ctx, customer); err != nil {
			return err
		}
		if r.withoutArea, err = tx.ActiveAssetsWithoutAreaOfCustomer(ctx, customer); err != nil {
			return err
		}
		if r.facts, err = tx.FindingAreaFactsOfCustomer(ctx, customer, since); err != nil {
			return err
		}
		r.scores, err = tx.ScoresOf(ctx, openCritical(r.facts))
		return err
	})
	return r, err
}

func openCritical(facts []postgres.FindingAreaFact) []finding.ID {
	var ids []finding.ID
	for _, f := range facts {
		if band, _ := f.Score.Band(); f.ClosedAt == nil && band == scoring.BandCritical {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

func (t *areaTally) addOpen(f postgres.FindingAreaFact, history []postgres.TimedScore, now time.Time) {
	h := &t.health
	if f.ClosedAt != nil || f.Score.Model == 0 {
		return
	}
	h.Open.Add(f.Score)
	if band, _ := f.Score.Band(); band == scoring.BandCritical {
		if days := criticalDays(history, now); h.OldestCriticalDays == nil || days > *h.OldestCriticalDays {
			h.OldestCriticalDays = &days
		}
	}
}

func (t *areaTally) addWindow(f postgres.FindingAreaFact, windowStart time.Time) {
	h := &t.health
	if f.FirstOpenedAt.Before(windowStart) && (f.ClosedAt == nil || !f.ClosedAt.Before(windowStart)) {
		h.Open30DaysAgo++
	}
	if f.ClosedAt != nil && !f.ClosedAt.Before(windowStart) && BucketOf(f.Reason) == Fixed {
		h.Fixed++
	}
}

func (t *areaTally) addWeeks(f postgres.FindingAreaFact, thisWeek time.Time) {
	for i := range GrowingWeeks {
		start := thisWeek.AddDate(0, 0, -7*(i+1))
		end := start.AddDate(0, 0, 7)
		if within(f.FirstOpenedAt, start, end) {
			t.opened[i]++
		}
		if f.ClosedAt != nil && within(*f.ClosedAt, start, end) {
			t.closed[i]++
		}
	}
}

// criticalDays is the whole days from the start of the latest unbroken run of
// Critical Scores in history, newest first, to now. A Score without a Band
// breaks the run.
func criticalDays(history []postgres.TimedScore, now time.Time) int {
	start := now
	for _, s := range history {
		if band, ok := s.Score.Band(); !ok || band != scoring.BandCritical {
			break
		}
		start = s.At
	}
	return int(now.Sub(start).Hours() / 24)
}

func within(t, start, end time.Time) bool { return !t.Before(start) && t.Before(end) }

func (t *areaTally) result() AreaHealth {
	h := t.health
	h.Reasons = []HealthReason{}
	if h.OldestCriticalDays != nil && *h.OldestCriticalDays > AgingCriticalDays {
		h.Reasons = append(h.Reasons, AgingCritical)
	}
	growing := true
	for i := range GrowingWeeks {
		growing = growing && t.opened[i] > t.closed[i]
	}
	if growing {
		h.Reasons = append(h.Reasons, Growing)
	}
	return h
}

func compareFlagged(a, b AreaHealth) int {
	switch {
	case a.NeedsHelp() == b.NeedsHelp():
		return 0
	case a.NeedsHelp():
		return -1
	default:
		return 1
	}
}

func compareOldestCritical(a, b AreaHealth) int {
	switch {
	case a.OldestCriticalDays == nil && b.OldestCriticalDays == nil:
		return 0
	case a.OldestCriticalDays == nil:
		return 1
	case b.OldestCriticalDays == nil:
		return -1
	default:
		return cmp.Compare(*b.OldestCriticalDays, *a.OldestCriticalDays)
	}
}
