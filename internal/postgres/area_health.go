package postgres

import (
	"context"
	"fmt"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/scoring"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

// AreaAssets is an Active Area of a Customer with how many Active Assets
// reference it.
type AreaAssets struct {
	ID         int64
	Name       string
	OwnerEmail *string
	AssetCount int
}

// ActiveAreaAssetsOfCustomer is the Customer's Active Areas, sorted by name,
// then id, with their Active Asset counts.
func (t *Tx) ActiveAreaAssetsOfCustomer(ctx context.Context, customer tenancy.CustomerID) ([]AreaAssets, error) {
	rows, err := t.q.ListActiveAreasOfCustomerWithAssetCounts(ctx, uuid.UUID(customer))
	if err != nil {
		return nil, fmt.Errorf("list active areas of customer %s: %w", customer, err)
	}
	out := make([]AreaAssets, len(rows))
	for i, row := range rows {
		out[i] = AreaAssets{ID: row.ID, Name: row.Name, OwnerEmail: row.OwnerEmail, AssetCount: int(row.AssetCount)}
	}
	return out, nil
}

// ActiveAssetsWithoutAreaOfCustomer counts the Customer's Active Assets that
// reference no Area.
func (t *Tx) ActiveAssetsWithoutAreaOfCustomer(ctx context.Context, customer tenancy.CustomerID) (int, error) {
	n, err := t.q.CountActiveAssetsWithoutAreaOfCustomer(ctx, uuid.UUID(customer))
	if err != nil {
		return 0, fmt.Errorf("count active assets without area of customer %s: %w", customer, err)
	}
	return int(n), nil
}

// FindingAreaFact is a Finding of a Customer's Assets with its Asset's Area.
type FindingAreaFact struct {
	ID finding.ID
	// AreaID is nil when the Asset has no Area.
	AreaID        *int64
	FirstOpenedAt time.Time
	// ClosedAt is nil while it is open; Reason is then 0.
	ClosedAt *time.Time
	Reason   finding.CloseReason
	// Score is its latest Score, the zero Score when it has none.
	Score scoring.Score
}

// FindingAreaFactsOfCustomer is every Finding of the Customer's Assets open
// now or closed at or after since, read in one query. A reopened Finding keeps
// only its latest close.
func (t *Tx) FindingAreaFactsOfCustomer(ctx context.Context, customer tenancy.CustomerID, since time.Time) ([]FindingAreaFact, error) {
	rows, err := t.q.ListFindingAreaFactsOfCustomer(ctx, sqlcgen.ListFindingAreaFactsOfCustomerParams{CustomerID: uuid.UUID(customer), Since: since})
	if err != nil {
		return nil, fmt.Errorf("list finding area facts of customer %s: %w", customer, err)
	}
	facts := make([]FindingAreaFact, len(rows))
	for i, row := range rows {
		facts[i] = FindingAreaFact{
			ID:            finding.ID(row.ID),
			AreaID:        row.AreaID,
			FirstOpenedAt: row.FirstOpenedAt.UTC(),
			Score:         latestScore(row.Model, row.Value),
		}
		if row.ClosedAt != nil {
			closed := row.ClosedAt.UTC()
			facts[i].ClosedAt = &closed
			facts[i].Reason = finding.CloseReason(valueOrZero(row.CloseReasonID))
		}
	}
	return facts, nil
}

// TimedScore is a Score with when it was scored.
type TimedScore struct {
	At    time.Time
	Score scoring.Score
}

// ScoresOf is every Score of the Findings with ids, newest first, read in one
// query.
func (t *Tx) ScoresOf(ctx context.Context, ids []finding.ID) (map[finding.ID][]TimedScore, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	raw := make([]uuid.UUID, len(ids))
	for i, id := range ids {
		raw[i] = uuid.UUID(id)
	}
	rows, err := t.q.ListFindingScoresOf(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("list scores of %d findings: %w", len(ids), err)
	}
	out := make(map[finding.ID][]TimedScore, len(ids))
	for _, row := range rows {
		id := finding.ID(row.FindingID)
		out[id] = append(out[id], TimedScore{At: row.ScoredAt.UTC(), Score: latestScore(row.Model, row.Value)})
	}
	return out, nil
}
