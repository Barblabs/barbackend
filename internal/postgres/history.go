package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

// FindingVersion is one of a Customer's Prioritizations as a Finding's
// history reads it (ADR 0036): when it was made, the Business Context version
// its Prioritizer read, 0 for none, and the Finding's place in it, nil when it
// does not hold the Finding.
type FindingVersion struct {
	Prioritization  uuid.UUID
	Created         time.Time
	BusinessContext int
	Place           *FindingPlace
}

// FindingPlace is where a Prioritization holds a Finding.
type FindingPlace struct {
	Placement uuid.UUID
	Placed    time.Time
	Group     int
	ScoreRank int
}

// FindingVersions is the Customer's Prioritizations from the first that holds
// the Finding on, oldest first; none when no Prioritization ever held it.
func (t *Tx) FindingVersions(ctx context.Context, customer tenancy.CustomerID, finding uuid.UUID) ([]FindingVersion, error) {
	rows, err := t.q.ListFindingVersions(ctx, sqlcgen.ListFindingVersionsParams{FindingID: finding, CustomerID: uuid.UUID(customer)})
	if err != nil {
		return nil, fmt.Errorf("list the prioritizations of finding %s: %w", finding, err)
	}
	out := make([]FindingVersion, len(rows))
	for i, r := range rows {
		out[i] = FindingVersion{Prioritization: r.ID, Created: r.CreatedAt, BusinessContext: int(valueOrZero(r.BusinessContextVersion))}
		if r.PlacementID.Valid {
			out[i].Place = &FindingPlace{
				Placement: uuid.UUID(r.PlacementID.Bytes), Placed: valueOrZero(r.PlacedAt),
				Group: int(valueOrZero(r.GroupPosition)), ScoreRank: int(valueOrZero(r.ScoreRank)),
			}
		}
	}
	return out, nil
}

// PrioritizationContents is, by id, the content of those of the Customer's
// Prioritizations among ids, opaque here.
func (t *Tx) PrioritizationContents(ctx context.Context, customer tenancy.CustomerID, ids []uuid.UUID) (map[uuid.UUID]json.RawMessage, error) {
	rows, err := t.q.ListPrioritizationContents(ctx, sqlcgen.ListPrioritizationContentsParams{CustomerID: uuid.UUID(customer), Ids: ids})
	if err != nil {
		return nil, fmt.Errorf("list the contents of %d prioritizations: %w", len(ids), err)
	}
	out := make(map[uuid.UUID]json.RawMessage, len(rows))
	for _, r := range rows {
		out[r.ID] = r.Content
	}
	return out, nil
}

// PlacementDossiers is, by id, the Dossier of those placements among ids of a
// Finding of the Customer's Assets, opaque here.
func (t *Tx) PlacementDossiers(ctx context.Context, customer tenancy.CustomerID, finding uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]json.RawMessage, error) {
	rows, err := t.q.ListPlacementDossiers(ctx, sqlcgen.ListPlacementDossiersParams{CustomerID: uuid.UUID(customer), FindingID: finding, Ids: ids})
	if err != nil {
		return nil, fmt.Errorf("list the dossiers of finding %s: %w", finding, err)
	}
	out := make(map[uuid.UUID]json.RawMessage, len(rows))
	for _, r := range rows {
		out[r.ID] = r.Dossier
	}
	return out, nil
}

// FeedbackOnFinding is every Feedback on the Finding in the Customer's
// Prioritizations, oldest first.
func (t *Tx) FeedbackOnFinding(ctx context.Context, customer tenancy.CustomerID, finding uuid.UUID) ([]StoredFeedback, error) {
	rows, err := t.q.ListFeedbackOnFinding(ctx, sqlcgen.ListFeedbackOnFindingParams{CustomerID: uuid.UUID(customer), FindingID: finding})
	if err != nil {
		return nil, fmt.Errorf("list feedback on finding %s: %w", finding, err)
	}
	out := make([]StoredFeedback, len(rows))
	for i, r := range rows {
		out[i] = restoreFeedback(sqlcgen.ListPrioritizationFeedbackRow(r))
	}
	return out, nil
}
