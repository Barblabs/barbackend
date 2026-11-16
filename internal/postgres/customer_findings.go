package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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

// FindingWeek is how many Findings of a Customer's Assets were first opened
// and how many were closed in one week, and how many were open when it ended.
type FindingWeek struct {
	// Start is when the week starts; it lasts 168 hours.
	Start     time.Time
	Opened    int
	Closed    int
	OpenAtEnd int
}

// FindingWeeksOfCustomer are the weeks ahead of since, weeks of them, oldest
// first, each counted even when nothing happened in it. A reopened Finding
// counts only its latest close, and as open while it was closed before, since
// a Finding keeps no history of its closes.
func (t *Tx) FindingWeeksOfCustomer(ctx context.Context, customer tenancy.CustomerID, since time.Time, weeks int) ([]FindingWeek, error) {
	rows, err := t.q.CountFindingsOfCustomerByWeek(ctx, sqlcgen.CountFindingsOfCustomerByWeekParams{
		CustomerID: uuid.UUID(customer),
		Since:      since,
		LastStart:  since.Add(time.Duration(weeks-1) * week),
	})
	if err != nil {
		return nil, fmt.Errorf("count findings of customer %s by week: %w", customer, err)
	}
	counted := make([]FindingWeek, len(rows))
	for i, row := range rows {
		counted[i] = FindingWeek{Start: row.Week.UTC(), Opened: int(row.Opened), Closed: int(row.Closed), OpenAtEnd: int(row.OpenAtEnd)}
	}
	return counted, nil
}

const week = 168 * time.Hour

// AssetFindingBands counts an Asset's open Findings by the Score Band of
// their latest Score.
type AssetFindingBands struct {
	// AssetID is the Asset's handle, as StoredAsset.ID.
	AssetID                     int64
	AssetName                   string
	Critical, High, Medium, Low int
	// Unbanded counts the Findings whose latest Score is from a Scoring
	// Model without Bands, before Model 3 (ADR 0032).
	Unbanded int
}

// FindingBandsByAssetOfCustomer is, for every Asset of the Customer with an
// open scored Finding, how many it has in each Score Band, ordered as Assets
// are listed. A Finding not scored yet is left out.
func (t *Tx) FindingBandsByAssetOfCustomer(ctx context.Context, customer tenancy.CustomerID) ([]AssetFindingBands, error) {
	rows, err := t.q.ListOpenFindingScoresByAssetOfCustomer(ctx, uuid.UUID(customer))
	if err != nil {
		return nil, fmt.Errorf("list open finding scores of customer %s: %w", customer, err)
	}
	var assets []AssetFindingBands
	for _, row := range rows {
		if len(assets) == 0 || assets[len(assets)-1].AssetID != row.AssetID {
			assets = append(assets, AssetFindingBands{AssetID: row.AssetID, AssetName: row.AssetName})
		}
		counts := &assets[len(assets)-1]
		band, ok := scoring.Score{Model: scoring.ModelVersion(row.Model), Value: row.Value}.Band()
		switch {
		case !ok:
			counts.Unbanded++
		case band == scoring.BandCritical:
			counts.Critical++
		case band == scoring.BandHigh:
			counts.High++
		case band == scoring.BandMedium:
			counts.Medium++
		default:
			counts.Low++
		}
	}
	return assets, nil
}

// OpenFindingFact is an open scored Finding of a Customer's Assets with what
// the dashboard counts it by.
type OpenFindingFact struct {
	ID          finding.ID
	AssetID     int64
	Criticality inventory.Criticality
	// Exposure is the Asset's effective Exposure: declared, else imported.
	Exposure inventory.Exposure
	// Area is nil for an Asset in no Area.
	Area    *AreaRef
	Product inventory.Product
	Version string
	CVE     string
	KEV     bool
	EPSS    *float64
	Band    scoring.Band
	// Banded is false when the latest Score is from a Scoring Model without
	// Bands; Band is then zero.
	Banded bool
}

// AreaRef names an Area by its handle, as in GET /areas.
type AreaRef struct {
	ID   int64
	Name string
}

// OpenFindingFactsOfCustomer is every open scored Finding of the Customer's
// Assets, read in one query. kevExtension and epssExtension are the ids of
// the kev/1 and epss/1 extension definitions.
func (t *Tx) OpenFindingFactsOfCustomer(ctx context.Context, customer tenancy.CustomerID, kevExtension, epssExtension string) ([]OpenFindingFact, error) {
	rows, err := t.q.ListOpenFindingFactsOfCustomer(ctx, sqlcgen.ListOpenFindingFactsOfCustomerParams{
		KevExtensionID: kevExtension, EpssExtensionID: epssExtension, CustomerID: uuid.UUID(customer),
	})
	if err != nil {
		return nil, fmt.Errorf("list open finding facts of customer %s: %w", customer, err)
	}
	facts := make([]OpenFindingFact, len(rows))
	for i, row := range rows {
		f := OpenFindingFact{
			ID:          finding.ID(row.ID),
			AssetID:     row.AssetID,
			Criticality: inventory.Criticality(valueOrZero(row.CriticalityID)),
			Exposure:    inventory.Exposure(valueOrZero(row.ExposureID)),
			Product:     inventory.Product{Vendor: row.ProductVendor, Name: row.ProductName},
			Version:     row.ComponentVersion,
			CVE:         row.CveID,
			KEV:         row.Kev,
		}
		if row.AreaID != nil {
			f.Area = &AreaRef{ID: *row.AreaID, Name: valueOrZero(row.AreaName)}
		}
		if p, ok := row.Epss.(float64); ok {
			f.EPSS = &p
		}
		f.Band, f.Banded = scoring.Score{Model: scoring.ModelVersion(row.Model), Value: row.Value}.Band()
		facts[i] = f
	}
	return facts, nil
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
					ExploitSignal:       row.ExploitSignal, ClassificationMultiplier: row.InformationClassificationMultiplier,
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
