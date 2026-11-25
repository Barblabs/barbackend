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

// OpenFindingFact is an open scored Finding of a Customer's Assets with what
// the dashboard counts it by.
type OpenFindingFact struct {
	// Exposure is the Asset's effective Exposure: declared, else imported.
	Exposure inventory.Exposure
	CVE      string
	KEV      bool
	// Score is the latest Score's Model and value, which give its Band.
	Score scoring.Score
}

// OpenFindingFactsOfCustomer is every open scored Finding of the Customer's
// Assets, read in one query. kevExtension is the id of the kev/1 extension
// definition.
func (t *Tx) OpenFindingFactsOfCustomer(ctx context.Context, customer tenancy.CustomerID, kevExtension string) ([]OpenFindingFact, error) {
	rows, err := t.q.ListOpenFindingFactsOfCustomer(ctx, sqlcgen.ListOpenFindingFactsOfCustomerParams{
		KevExtensionID: kevExtension, CustomerID: uuid.UUID(customer),
	})
	if err != nil {
		return nil, fmt.Errorf("list open finding facts of customer %s: %w", customer, err)
	}
	facts := make([]OpenFindingFact, len(rows))
	for i, row := range rows {
		facts[i] = OpenFindingFact{
			Exposure: inventory.Exposure(valueOrZero(row.ExposureID)),
			CVE:      row.CveID,
			KEV:      row.Kev,
			Score:    latestScore(row.Model, row.Value),
		}
	}
	return facts, nil
}

// FindingClose is whether a Finding of a Customer's Assets is closed, and why.
type FindingClose struct {
	Closed bool
	Reason finding.CloseReason
}

// FindingCloseOfCustomer reads whether a Finding of the Customer's Assets is
// closed. It fails with ErrNotFound when the Customer has no such Finding.
func (t *Tx) FindingCloseOfCustomer(ctx context.Context, customer tenancy.CustomerID, id finding.ID) (FindingClose, error) {
	row, err := t.q.GetFindingCloseOfCustomer(ctx, sqlcgen.GetFindingCloseOfCustomerParams{CustomerID: uuid.UUID(customer), ID: uuid.UUID(id)})
	if errors.Is(err, pgx.ErrNoRows) {
		return FindingClose{}, fmt.Errorf("finding %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return FindingClose{}, fmt.Errorf("get close of finding %s: %w", id, err)
	}
	if row.CloseReasonID == nil {
		return FindingClose{}, nil
	}
	return FindingClose{Closed: true, Reason: finding.CloseReason(*row.CloseReasonID)}, nil
}

// ReopenFindingByHand reopens a Finding of the Customer's Assets that a User
// closed (ADR 0035). It reports false, changing nothing, when the Customer has
// no such Finding closed by hand.
func (t *Tx) ReopenFindingByHand(ctx context.Context, customer tenancy.CustomerID, id finding.ID) (bool, error) {
	n, err := t.q.ReopenFindingByHand(ctx, sqlcgen.ReopenFindingByHandParams{CustomerID: uuid.UUID(customer), ID: uuid.UUID(id)})
	if err != nil {
		return false, fmt.Errorf("reopen finding %s by hand: %w", id, err)
	}
	return n > 0, nil
}

// FindingClosedByHand is a Finding of a Customer's Assets that a User closed,
// with its Asset and the close (ADR 0035).
type FindingClosedByHand struct {
	ID               finding.ID
	CVE              string
	AssetID          int64
	AssetName        string
	Product          inventory.Product
	ComponentName    string
	ComponentVersion string
	Reason           finding.CloseReason
	Closed           time.Time
	Note             string
	ReopenAt         *time.Time
	ClosedByEmail    string
}

// FindingsOfCustomerClosedByHand is the Findings of the Customer's Assets that
// a User closed, newest close first.
func (t *Tx) FindingsOfCustomerClosedByHand(ctx context.Context, customer tenancy.CustomerID) ([]FindingClosedByHand, error) {
	rows, err := t.q.ListFindingsOfCustomerClosedByHand(ctx, uuid.UUID(customer))
	if err != nil {
		return nil, fmt.Errorf("list findings of customer %s closed by hand: %w", customer, err)
	}
	out := make([]FindingClosedByHand, len(rows))
	for i, r := range rows {
		out[i] = FindingClosedByHand{
			ID: finding.ID(r.ID), CVE: r.CveID, AssetID: r.AssetID, AssetName: r.AssetName,
			Product:       inventory.Product{Vendor: r.ProductVendor, Name: r.ProductName},
			ComponentName: r.ComponentName, ComponentVersion: r.ComponentVersion,
			Reason: finding.CloseReason(r.CloseReasonID), Closed: r.ClosedAt, Note: r.CloseNote,
			ReopenAt: r.ReopenAt, ClosedByEmail: r.ClosedByEmail,
		}
	}
	return out, nil
}

func latestScore(model int16, value float64) scoring.Score {
	return scoring.Score{Model: scoring.ModelVersion(model), Value: value}
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
