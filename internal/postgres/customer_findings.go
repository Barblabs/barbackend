package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/scoring"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CustomerFinding is a Finding as its Dossier is built from: its Asset, the
// Software Component it was matched on, its Vulnerability's STIX object with
// the extensions of every Feed, and its latest Score (ADR 0026).
type CustomerFinding struct {
	ID               finding.ID
	Asset            *inventory.Asset
	CVE              string
	ComponentName    string
	ComponentVersion string
	Vulnerability    json.RawMessage
	Score            scoring.Score
}

// OpenFindingsOfCustomer is the open Findings of the Customer's Assets that
// have a Score, read in a fixed number of queries whatever their number.
func (t *Tx) OpenFindingsOfCustomer(ctx context.Context, customer tenancy.CustomerID) ([]CustomerFinding, error) {
	rows, err := t.q.ListOpenFindingsOfCustomer(ctx, uuid.UUID(customer))
	if err != nil {
		return nil, fmt.Errorf("list open findings of customer %s: %w", customer, err)
	}
	return t.customerFindings(ctx, rows)
}

// FindingOfCustomer is one Finding of the Customer's Assets, open or closed.
// It fails with ErrNotFound when the Customer has no such Finding with a
// Score.
func (t *Tx) FindingOfCustomer(ctx context.Context, customer tenancy.CustomerID, id uuid.UUID) (CustomerFinding, error) {
	row, err := t.q.GetFindingOfCustomer(ctx, sqlcgen.GetFindingOfCustomerParams{CustomerID: uuid.UUID(customer), ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return CustomerFinding{}, fmt.Errorf("finding %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return CustomerFinding{}, fmt.Errorf("get finding %s: %w", id, err)
	}
	found, err := t.customerFindings(ctx, []sqlcgen.ListOpenFindingsOfCustomerRow{sqlcgen.ListOpenFindingsOfCustomerRow(row)})
	if err != nil {
		return CustomerFinding{}, err
	}
	return found[0], nil
}

func (t *Tx) customerFindings(ctx context.Context, rows []sqlcgen.ListOpenFindingsOfCustomerRow) ([]CustomerFinding, error) {
	refs := make([]inventory.SourceReference, len(rows))
	for i, row := range rows {
		refs[i] = inventory.SourceReference{Source: inventory.CMDBSourceID(row.CmdbSourceID), RecordID: row.RecordID}
	}
	assets, err := t.assetsByReference(ctx, refs)
	if err != nil {
		return nil, err
	}
	out := make([]CustomerFinding, len(rows))
	for i, row := range rows {
		asset, ok := assets[refs[i]]
		if !ok {
			return nil, fmt.Errorf("finding %s: asset %v: %w", row.ID, refs[i], ErrNotFound)
		}
		gaps := make([]scoring.DataGap, len(row.Gaps))
		for j, g := range row.Gaps {
			gaps[j] = scoring.DataGap(g)
		}
		out[i] = CustomerFinding{
			ID:               finding.ID(row.ID),
			Asset:            asset,
			CVE:              row.CveID,
			ComponentName:    row.ComponentName,
			ComponentVersion: row.ComponentVersion,
			Vulnerability:    row.VulnerabilityObject,
			Score: scoring.Score{
				Model: scoring.ModelVersion(row.Model),
				Value: row.Value,
				Factors: scoring.Factors{
					Alpha: row.Alpha, Beta: row.Beta, Gamma: row.Gamma, Vulnerability: row.Vulnerability,
					CriticalityMultiplier: row.CriticalityMultiplier, ExposureMultiplier: row.ExposureMultiplier,
					LifecycleMultiplier: row.LifecycleMultiplier,
				},
				Gaps: gaps,
			},
		}
	}
	return out, nil
}

// assetsByReference reads the Assets of refs with their Software Components,
// in two queries.
func (t *Tx) assetsByReference(ctx context.Context, refs []inventory.SourceReference) (map[inventory.SourceReference]*inventory.Asset, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	sources := make([]uuid.UUID, len(refs))
	records := make([]string, len(refs))
	for i, ref := range refs {
		sources[i], records[i] = uuid.UUID(ref.Source), ref.RecordID
	}
	rows, err := t.q.ListAssetsByReference(ctx, sqlcgen.ListAssetsByReferenceParams{SourceIds: sources, RecordIds: records})
	if err != nil {
		return nil, fmt.Errorf("list %d assets: %w", len(refs), err)
	}
	components, err := t.q.ListSoftwareComponentsOf(ctx, sqlcgen.ListSoftwareComponentsOfParams{SourceIds: sources, RecordIds: records})
	if err != nil {
		return nil, fmt.Errorf("list software of %d assets: %w", len(refs), err)
	}
	software := softwareByAsset(components)
	out := make(map[inventory.SourceReference]*inventory.Asset, len(rows))
	for _, row := range rows {
		ref := inventory.SourceReference{Source: inventory.CMDBSourceID(row.CmdbSourceID), RecordID: row.RecordID}
		if out[ref], err = restoreAssetValues(ref, sqlcgen.ListAssetsRow(row), software[ref]); err != nil {
			return nil, fmt.Errorf("restore asset %v: %w", ref, err)
		}
	}
	return out, nil
}
