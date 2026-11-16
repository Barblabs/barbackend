package findings

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

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

// ErrInvalidCount is a count of Findings asked for with a limit or a grouping
// it does not have.
var ErrInvalidCount = errors.New("invalid finding count")

type AreaRef = postgres.AreaRef

// BandCounts counts open Findings by the Score Band of their latest Score.
type BandCounts struct {
	Critical, High, Medium, Low int
	// Unbanded counts those whose latest Score is from a Scoring Model
	// without Bands, before Model 3 (ADR 0032).
	Unbanded int
}

func (c *BandCounts) add(f postgres.OpenFindingFact) {
	switch {
	case !f.Banded:
		c.Unbanded++
	case f.Band == scoring.BandCritical:
		c.Critical++
	case f.Band == scoring.BandHigh:
		c.High++
	case f.Band == scoring.BandMedium:
		c.Medium++
	default:
		c.Low++
	}
}

// Total is every Finding counted.
func (c BandCounts) Total() int { return c.Critical + c.High + c.Medium + c.Low + c.Unbanded }

// moreSevere orders counts with more Critical first, then more High, Medium
// and Low.
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
		sum.Bands.add(f)
		if f.KEV {
			sum.KEV++
		}
		if f.Banded && f.Band == scoring.BandCritical && f.Exposure == inventory.InternetFacing {
			sum.CriticalInternetFacing++
		}
	}
	return sum, nil
}

// Grouping is what Breakdown groups Findings by.
type Grouping int

const (
	ByExposure Grouping = iota + 1
	ByCriticality
	ByArea
)

// Group is the Findings of one value of a Grouping: only the field of that
// Grouping is set, and Area is nil for the Assets in no Area.
type Group struct {
	Exposure    inventory.Exposure
	Criticality inventory.Criticality
	Area        *AreaRef
	Bands       BandCounts
}

// Breakdown counts the Customer's open scored Findings by Score Band within
// each value of by, taking each Asset's effective Exposure. By Exposure and
// by Criticality every value is there, Unknown last, so a heatmap keeps its
// columns; by Area only the Areas with Findings are, by name, with the Assets
// in no Area last.
func (s *Service) Breakdown(ctx context.Context, caller tenancy.User, by Grouping) ([]Group, error) {
	if by < ByExposure || by > ByArea {
		return nil, fmt.Errorf("%w: grouping %d", ErrInvalidCount, by)
	}
	facts, err := s.openFacts(ctx, caller)
	if err != nil {
		return nil, err
	}
	switch by {
	case ByExposure:
		groups := []Group{{Exposure: inventory.InternetFacing}, {Exposure: inventory.Internal}, {Exposure: inventory.ExposureUnknown}}
		for _, f := range facts {
			groups[slices.IndexFunc(groups, func(g Group) bool { return g.Exposure == f.Exposure })].Bands.add(f)
		}
		return groups, nil
	case ByCriticality:
		groups := []Group{{Criticality: inventory.CriticalityHigh}, {Criticality: inventory.CriticalityMedium}, {Criticality: inventory.CriticalityLow}, {Criticality: inventory.CriticalityUnknown}}
		for _, f := range facts {
			groups[slices.IndexFunc(groups, func(g Group) bool { return g.Criticality == f.Criticality })].Bands.add(f)
		}
		return groups, nil
	default:
		return byArea(facts), nil
	}
}

func byArea(facts []postgres.OpenFindingFact) []Group {
	var groups []Group
	for _, f := range facts {
		i := slices.IndexFunc(groups, func(g Group) bool {
			return (g.Area == nil && f.Area == nil) || (g.Area != nil && f.Area != nil && g.Area.ID == f.Area.ID)
		})
		if i < 0 {
			groups = append(groups, Group{Area: f.Area})
			i = len(groups) - 1
		}
		groups[i].Bands.add(f)
	}
	slices.SortFunc(groups, func(a, b Group) int {
		switch {
		case a.Area == nil:
			return 1
		case b.Area == nil:
			return -1
		}
		return cmp.Or(strings.Compare(strings.ToLower(a.Area.Name), strings.ToLower(b.Area.Name)), cmp.Compare(a.Area.ID, b.Area.ID))
	})
	return groups
}

// ComponentCount is the open Findings of one Product at one version: an
// update of it closes them.
type ComponentCount struct {
	Product inventory.Product
	Version string
	Assets  int
	Bands   BandCounts
}

// CVECount is the open Findings of one Vulnerability.
type CVECount struct {
	CVE    string
	KEV    bool
	EPSS   *float64
	Assets int
	Bands  BandCounts
}

// Top is the components and the CVEs with the most severe open Findings.
type Top struct {
	Components []ComponentCount
	CVEs       []CVECount
}

// Top is at most limit components and limit CVEs of the Customer's open
// scored Findings, each ordered by its Findings' Score Bands, most Critical
// first, then by how many Findings it has. A zero limit takes
// DefaultTopLimit. It fails with ErrInvalidCount.
func (s *Service) Top(ctx context.Context, caller tenancy.User, limit int) (Top, error) {
	if limit == 0 {
		limit = DefaultTopLimit
	}
	if limit < 1 || limit > MaxTopLimit {
		return Top{}, fmt.Errorf("%w: limit must be a number from 1 to %d", ErrInvalidCount, MaxTopLimit)
	}
	facts, err := s.openFacts(ctx, caller)
	if err != nil {
		return Top{}, err
	}
	type component struct {
		product inventory.Product
		version string
	}
	components := map[component]*ComponentCount{}
	cves := map[string]*CVECount{}
	componentAssets := map[component]map[int64]bool{}
	cveAssets := map[string]map[int64]bool{}
	for _, f := range facts {
		key := component{f.Product, f.Version}
		if components[key] == nil {
			components[key] = &ComponentCount{Product: f.Product, Version: f.Version}
			componentAssets[key] = map[int64]bool{}
		}
		components[key].Bands.add(f)
		componentAssets[key][f.AssetID] = true
		if cves[f.CVE] == nil {
			cves[f.CVE] = &CVECount{CVE: f.CVE, KEV: f.KEV, EPSS: f.EPSS}
			cveAssets[f.CVE] = map[int64]bool{}
		}
		cves[f.CVE].Bands.add(f)
		cveAssets[f.CVE][f.AssetID] = true
	}
	var top Top
	for key, c := range components {
		c.Assets = len(componentAssets[key])
		top.Components = append(top.Components, *c)
	}
	for cve, c := range cves {
		c.Assets = len(cveAssets[cve])
		top.CVEs = append(top.CVEs, *c)
	}
	slices.SortFunc(top.Components, func(a, b ComponentCount) int {
		return cmp.Or(moreSevere(a.Bands, b.Bands), cmp.Compare(b.Bands.Total(), a.Bands.Total()),
			strings.Compare(a.Product.Vendor+" "+a.Product.Name+" "+a.Version, b.Product.Vendor+" "+b.Product.Name+" "+b.Version))
	})
	slices.SortFunc(top.CVEs, func(a, b CVECount) int {
		return cmp.Or(moreSevere(a.Bands, b.Bands), cmp.Compare(b.Bands.Total(), a.Bands.Total()), strings.Compare(a.CVE, b.CVE))
	})
	top.Components = top.Components[:min(limit, len(top.Components))]
	top.CVEs = top.CVEs[:min(limit, len(top.CVEs))]
	return top, nil
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
