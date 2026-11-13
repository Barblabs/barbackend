package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/matching"
	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/scoring"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Candidate is a Software Component of an Active Asset that can be matched,
// with what scoring needs of its Asset. Position is the component's place in
// its Asset, which breaks ties between two installations of one Product
// (ADR 0020).
type Candidate struct {
	Asset       inventory.SourceReference
	Position    int
	Component   inventory.SoftwareComponent
	Criticality inventory.Criticality
	Exposure    inventory.Exposure
}

// OpenFinding is an open Finding with what scoring needs of its Asset.
type OpenFinding struct {
	ID               finding.ID
	Key              finding.Key
	ComponentName    string
	ComponentVersion string
	Criticality      inventory.Criticality
	Exposure         inventory.Exposure
}

// ComponentsWithProducts is the Software Components of every Active Asset, of
// every Customer, that have one of products, ignoring case. It is what a new
// Vulnerability is matched against (ADR 0020).
func (t *Tx) ComponentsWithProducts(ctx context.Context, products []inventory.Product) ([]Candidate, error) {
	if len(products) == 0 {
		return nil, nil
	}
	vendors, names := productKeys(products)
	rows, err := t.q.ListActiveComponentsWithProducts(ctx, sqlcgen.ListActiveComponentsWithProductsParams{Vendors: vendors, Products: names})
	if err != nil {
		return nil, fmt.Errorf("list components with %d products: %w", len(products), err)
	}
	out := make([]Candidate, len(rows))
	for i, row := range rows {
		out[i] = candidate(row)
	}
	return out, nil
}

// ComponentsOfSource is the Software Components of the CMDB Source's Active
// Assets. It is what a Sync matches against the stored Vulnerabilities
// (ADR 0020).
func (t *Tx) ComponentsOfSource(ctx context.Context, source inventory.CMDBSourceID) ([]Candidate, error) {
	rows, err := t.q.ListActiveComponentsOfSource(ctx, uuid.UUID(source))
	if err != nil {
		return nil, fmt.Errorf("list components of source %s: %w", source, err)
	}
	out := make([]Candidate, len(rows))
	for i, row := range rows {
		out[i] = candidate(sqlcgen.ListActiveComponentsWithProductsRow(row))
	}
	return out, nil
}

// SaveMatch opens the Finding of m, updates it when it is open or reopens it
// when it was closed, and replaces its Match Flags with m's, in one
// transaction. It returns the Finding's ID, which never changes, and what it
// did.
func (t *Tx) SaveMatch(ctx context.Context, m finding.Match) (finding.ID, finding.Outcome, error) {
	evidence, err := json.Marshal(m.Evidence)
	if err != nil {
		return finding.ID{}, 0, fmt.Errorf("encode evidence of %s: %w", m.Key.CVE, err)
	}
	row, err := t.q.UpsertFinding(ctx, sqlcgen.UpsertFindingParams{
		ID:               uuid.New(),
		CmdbSourceID:     uuid.UUID(m.Key.Asset.Source),
		RecordID:         m.Key.Asset.RecordID,
		ProductVendor:    m.Key.Vendor,
		ProductName:      m.Key.Product,
		CveID:            m.Key.CVE,
		ComponentName:    m.Component.Name,
		ComponentVersion: m.Component.Version,
		Evidence:         evidence,
	})
	if err != nil {
		return finding.ID{}, 0, fmt.Errorf("save finding of %s on %s: %w", m.Key.CVE, m.Key.Asset.RecordID, err)
	}
	if err := t.replaceMatchFlags(ctx, row.ID, m.Flags); err != nil {
		return finding.ID{}, 0, err
	}
	outcome := finding.Updated
	switch {
	case row.Existed == 0:
		outcome = finding.Opened
	case row.WasClosed:
		outcome = finding.Reopened
	}
	return finding.ID(row.ID), outcome, nil
}

func (t *Tx) replaceMatchFlags(ctx context.Context, id uuid.UUID, flags []matching.Flag) error {
	if err := t.q.DeleteFindingMatchFlags(ctx, id); err != nil {
		return fmt.Errorf("delete match flags of finding %s: %w", id, err)
	}
	if len(flags) == 0 {
		return nil
	}
	rows := make([]sqlcgen.InsertFindingMatchFlagsParams, len(flags))
	for i, f := range flags {
		rows[i] = sqlcgen.InsertFindingMatchFlagsParams{FindingID: id, FlagID: int16(f)}
	}
	if _, err := t.q.InsertFindingMatchFlags(ctx, rows); err != nil {
		return fmt.Errorf("insert match flags of finding %s: %w", id, err)
	}
	return nil
}

// MatchFlags is the Match Flags of the Finding's current match, in catalog
// order; none means a certain match.
func (t *Tx) MatchFlags(ctx context.Context, id finding.ID) ([]matching.Flag, error) {
	ids, err := t.q.ListFindingMatchFlags(ctx, uuid.UUID(id))
	if err != nil {
		return nil, fmt.Errorf("list match flags of finding %s: %w", id, err)
	}
	flags := make([]matching.Flag, len(ids))
	for i, id := range ids {
		flags[i] = matching.Flag(id)
	}
	return flags, nil
}

// CloseFinding closes an open Finding for reason. It reports false, changing
// nothing, when the Finding was already closed.
func (t *Tx) CloseFinding(ctx context.Context, id finding.ID, reason finding.CloseReason) (bool, error) {
	n, err := t.q.CloseFinding(ctx, sqlcgen.CloseFindingParams{ID: uuid.UUID(id), CloseReasonID: ptr(int16(reason))})
	if err != nil {
		return false, fmt.Errorf("close finding %s: %w", id, err)
	}
	return n > 0, nil
}

// CloseFindingsOfInactiveAssets closes, as asset_inactive, the open Findings
// of the source's Assets that are Inactive, and returns how many it closed.
func (t *Tx) CloseFindingsOfInactiveAssets(ctx context.Context, source inventory.CMDBSourceID) (int, error) {
	n, err := t.q.CloseFindingsOfInactiveAssets(ctx, sqlcgen.CloseFindingsOfInactiveAssetsParams{
		CmdbSourceID: uuid.UUID(source), CloseReasonID: ptr(int16(finding.AssetInactive)),
	})
	if err != nil {
		return 0, fmt.Errorf("close findings of inactive assets of source %s: %w", source, err)
	}
	return int(n), nil
}

// OpenFindingsOfVulnerability is the open Findings of the CVE, which KEV and
// EPSS rescore and an NVD modification matches again.
func (t *Tx) OpenFindingsOfVulnerability(ctx context.Context, cve string) ([]OpenFinding, error) {
	rows, err := t.q.ListOpenFindingsOfVulnerability(ctx, cve)
	if err != nil {
		return nil, fmt.Errorf("list open findings of %s: %w", cve, err)
	}
	out := make([]OpenFinding, len(rows))
	for i, row := range rows {
		out[i] = openFinding(row)
	}
	return out, nil
}

// OpenFindingsOfSource is the open Findings of the CMDB Source's Assets,
// which a Sync closes when they no longer match.
func (t *Tx) OpenFindingsOfSource(ctx context.Context, source inventory.CMDBSourceID) ([]OpenFinding, error) {
	rows, err := t.q.ListOpenFindingsOfSource(ctx, uuid.UUID(source))
	if err != nil {
		return nil, fmt.Errorf("list open findings of source %s: %w", source, err)
	}
	out := make([]OpenFinding, len(rows))
	for i, row := range rows {
		out[i] = openFinding(sqlcgen.ListOpenFindingsOfVulnerabilityRow(row))
	}
	return out, nil
}

// OpenFindingsOfAsset is the open Findings of one Asset, with its effective
// Criticality and Exposure, which a Declaration rescores (ADR 0021).
func (t *Tx) OpenFindingsOfAsset(ctx context.Context, asset inventory.SourceReference) ([]OpenFinding, error) {
	rows, err := t.q.ListOpenFindingsOfAsset(ctx, sqlcgen.ListOpenFindingsOfAssetParams{CmdbSourceID: uuid.UUID(asset.Source), RecordID: asset.RecordID})
	if err != nil {
		return nil, fmt.Errorf("list open findings of asset %v: %w", asset, err)
	}
	out := make([]OpenFinding, len(rows))
	for i, row := range rows {
		out[i] = openFinding(sqlcgen.ListOpenFindingsOfVulnerabilityRow(row))
	}
	return out, nil
}

// SaveScoreIfChanged stores s as the Finding's newest Score unless its latest
// Score has the same Scoring Model, value and Data Gaps (ADR 0020). It
// reports whether it stored one.
func (t *Tx) SaveScoreIfChanged(ctx context.Context, id finding.ID, s scoring.Score) (bool, error) {
	latest, err := t.q.LatestFindingScore(ctx, uuid.UUID(id))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return false, fmt.Errorf("latest score of finding %s: %w", id, err)
	case sameScore(latest, s):
		return false, nil
	}
	scoredAt, err := t.q.InsertFindingScore(ctx, sqlcgen.InsertFindingScoreParams{
		FindingID:             uuid.UUID(id),
		Model:                 int16(s.Model),
		Value:                 s.Value,
		Alpha:                 s.Factors.Alpha,
		Beta:                  s.Factors.Beta,
		Gamma:                 s.Factors.Gamma,
		Vulnerability:         s.Factors.Vulnerability,
		CriticalityMultiplier: s.Factors.CriticalityMultiplier,
		ExposureMultiplier:    s.Factors.ExposureMultiplier,
		LifecycleMultiplier:   s.Factors.LifecycleMultiplier,
	})
	if err != nil {
		return false, fmt.Errorf("insert score of finding %s: %w", id, err)
	}
	if len(s.Gaps) == 0 {
		return true, nil
	}
	gaps := make([]sqlcgen.InsertFindingScoreDataGapsParams, len(s.Gaps))
	for i, g := range s.Gaps {
		gaps[i] = sqlcgen.InsertFindingScoreDataGapsParams{FindingID: uuid.UUID(id), ScoredAt: scoredAt, GapID: int16(g)}
	}
	if _, err := t.q.InsertFindingScoreDataGaps(ctx, gaps); err != nil {
		return false, fmt.Errorf("insert data gaps of finding %s: %w", id, err)
	}
	return true, nil
}

// LatestScore is the Finding's newest Score. It fails with ErrNotFound when
// the Finding was never scored.
func (t *Tx) LatestScore(ctx context.Context, id finding.ID) (scoring.Score, error) {
	row, err := t.q.LatestFindingScore(ctx, uuid.UUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return scoring.Score{}, fmt.Errorf("score of finding %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return scoring.Score{}, fmt.Errorf("latest score of finding %s: %w", id, err)
	}
	var gaps []scoring.DataGap
	for _, g := range row.Gaps {
		gaps = append(gaps, scoring.DataGap(g))
	}
	return scoring.Score{
		Model: scoring.ModelVersion(row.Model),
		Value: row.Value,
		Factors: scoring.Factors{
			Alpha: row.Alpha, Beta: row.Beta, Gamma: row.Gamma, Vulnerability: row.Vulnerability,
			CriticalityMultiplier: row.CriticalityMultiplier, ExposureMultiplier: row.ExposureMultiplier,
			LifecycleMultiplier: row.LifecycleMultiplier,
		},
		Gaps: gaps,
	}, nil
}

func sameScore(latest sqlcgen.LatestFindingScoreRow, s scoring.Score) bool {
	gaps := make([]int16, len(s.Gaps))
	for i, g := range s.Gaps {
		gaps[i] = int16(g)
	}
	return latest.Model == int16(s.Model) && latest.Value == s.Value && slices.Equal(latest.Gaps, gaps)
}

func candidate(row sqlcgen.ListActiveComponentsWithProductsRow) Candidate {
	return Candidate{
		Asset:    inventory.SourceReference{Source: inventory.CMDBSourceID(row.CmdbSourceID), RecordID: row.RecordID},
		Position: int(row.Position),
		Component: inventory.SoftwareComponent{
			Role:    inventory.SoftwareRole(row.RoleID),
			Name:    row.Name,
			Version: row.Version,
			Product: inventory.Product{Vendor: valueOrZero(row.ProductVendor), Name: valueOrZero(row.ProductName)},
		},
		Criticality: inventory.Criticality(valueOrZero(row.CriticalityID)),
		Exposure:    inventory.Exposure(valueOrZero(row.ExposureID)),
	}
}

func openFinding(row sqlcgen.ListOpenFindingsOfVulnerabilityRow) OpenFinding {
	return OpenFinding{
		ID: finding.ID(row.ID),
		Key: finding.Key{
			Asset:  inventory.SourceReference{Source: inventory.CMDBSourceID(row.CmdbSourceID), RecordID: row.RecordID},
			Vendor: row.ProductVendor, Product: row.ProductName, CVE: row.CveID,
		},
		ComponentName:    row.ComponentName,
		ComponentVersion: row.ComponentVersion,
		Criticality:      inventory.Criticality(valueOrZero(row.CriticalityID)),
		Exposure:         inventory.Exposure(valueOrZero(row.ExposureID)),
	}
}
