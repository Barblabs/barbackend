package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/assessment"
	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// StoredPrioritization is a Prioritization as the database records it: its
// content is opaque here.
type StoredPrioritization struct {
	ID       uuid.UUID
	Content  json.RawMessage
	Findings int
	Groups   int
	Created  time.Time
}

// PrioritizationSummary is a stored Prioritization without its content.
type PrioritizationSummary struct {
	ID       uuid.UUID
	Findings int
	Groups   int
	Created  time.Time
}

// CreatePrioritization stores p and returns when.
func (t *Tx) CreatePrioritization(ctx context.Context, customer tenancy.CustomerID, p StoredPrioritization) (time.Time, error) {
	created, err := t.q.InsertPrioritization(ctx, sqlcgen.InsertPrioritizationParams{
		ID:           p.ID,
		CustomerID:   uuid.UUID(customer),
		FindingCount: int32(p.Findings),
		GroupCount:   int32(p.Groups),
		Content:      p.Content,
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("insert prioritization %s: %w", p.ID, err)
	}
	return created, nil
}

// Prioritization fails with ErrNotFound when the Customer has no such
// Prioritization.
func (t *Tx) Prioritization(ctx context.Context, customer tenancy.CustomerID, id uuid.UUID) (StoredPrioritization, error) {
	row, err := t.q.GetPrioritization(ctx, sqlcgen.GetPrioritizationParams{ID: id, CustomerID: uuid.UUID(customer)})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredPrioritization{}, fmt.Errorf("prioritization %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return StoredPrioritization{}, fmt.Errorf("get prioritization %s: %w", id, err)
	}
	return StoredPrioritization{ID: row.ID, Content: row.Content, Created: row.CreatedAt}, nil
}

// ListPrioritizations is the Customer's Prioritizations, newest first.
func (t *Tx) ListPrioritizations(ctx context.Context, customer tenancy.CustomerID, limit int) ([]PrioritizationSummary, error) {
	rows, err := t.q.ListPrioritizations(ctx, sqlcgen.ListPrioritizationsParams{CustomerID: uuid.UUID(customer), PageSize: int32(limit)})
	if err != nil {
		return nil, fmt.Errorf("list prioritizations of customer %s: %w", customer, err)
	}
	list := make([]PrioritizationSummary, len(rows))
	for i, row := range rows {
		list[i] = PrioritizationSummary{ID: row.ID, Findings: int(row.FindingCount), Groups: int(row.GroupCount), Created: row.CreatedAt}
	}
	return list, nil
}

// PrioritizationHolds is whether the Customer's Prioritization holds the
// Finding of that id. It fails with ErrNotFound when the Customer has no such
// Prioritization.
func (t *Tx) PrioritizationHolds(ctx context.Context, customer tenancy.CustomerID, id uuid.UUID, finding string) (bool, error) {
	holds, err := t.q.PrioritizationHolds(ctx, sqlcgen.PrioritizationHoldsParams{FindingID: finding, ID: id, CustomerID: uuid.UUID(customer)})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("prioritization %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return false, fmt.Errorf("find finding %q in prioritization %s: %w", finding, id, err)
	}
	return holds, nil
}

// StoredPlan is an Action Plan for a Finding of a Prioritization: its content
// is opaque here.
type StoredPlan struct {
	ID      uuid.UUID
	Finding string
	Content json.RawMessage
	Created time.Time
}

// CreatePlan stores p on the Customer's Prioritization and returns when. It
// fails with ErrNotFound when the Customer has no such Prioritization.
func (t *Tx) CreatePlan(ctx context.Context, customer tenancy.CustomerID, prioritization uuid.UUID, p StoredPlan) (time.Time, error) {
	created, err := t.q.InsertActionPlan(ctx, sqlcgen.InsertActionPlanParams{
		ID:               p.ID,
		FindingID:        p.Finding,
		Content:          p.Content,
		PrioritizationID: prioritization,
		CustomerID:       uuid.UUID(customer),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, fmt.Errorf("prioritization %s: %w", prioritization, ErrNotFound)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("insert plan of %q in prioritization %s: %w", p.Finding, prioritization, err)
	}
	return created, nil
}

// LatestPlans are the newest Action Plan of each Finding of the Customer's
// Prioritization that has one.
func (t *Tx) LatestPlans(ctx context.Context, customer tenancy.CustomerID, prioritization uuid.UUID) ([]StoredPlan, error) {
	rows, err := t.q.ListLatestActionPlans(ctx, sqlcgen.ListLatestActionPlansParams{PrioritizationID: prioritization, CustomerID: uuid.UUID(customer)})
	if err != nil {
		return nil, fmt.Errorf("list plans of prioritization %s: %w", prioritization, err)
	}
	plans := make([]StoredPlan, len(rows))
	for i, row := range rows {
		plans[i] = StoredPlan{ID: row.ID, Finding: row.FindingID, Content: row.Content, Created: row.CreatedAt}
	}
	return plans, nil
}

// StoredFeedback is a User's verdict on a Finding of a Prioritization.
type StoredFeedback struct {
	ID          uuid.UUID
	Finding     string
	Author      tenancy.UserID
	Verdict     assessment.Verdict
	Note        string
	ViaAnalista bool
	Created     time.Time
}

// AddFeedback stores f on the Customer's Prioritization and returns it with
// its creation time. It fails with ErrNotFound when the Customer has no such
// Prioritization.
func (t *Tx) AddFeedback(ctx context.Context, customer tenancy.CustomerID, prioritization uuid.UUID, f StoredFeedback) (StoredFeedback, error) {
	created, err := t.q.InsertPrioritizationFeedback(ctx, sqlcgen.InsertPrioritizationFeedbackParams{
		ID:               f.ID,
		FindingID:        f.Finding,
		AuthorID:         uuid.UUID(f.Author),
		VerdictID:        int16(f.Verdict),
		Note:             f.Note,
		ViaAnalista:      f.ViaAnalista,
		PrioritizationID: prioritization,
		CustomerID:       uuid.UUID(customer),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredFeedback{}, fmt.Errorf("prioritization %s: %w", prioritization, ErrNotFound)
	}
	if err != nil {
		return StoredFeedback{}, fmt.Errorf("insert feedback on prioritization %s: %w", prioritization, err)
	}
	f.Created = created
	return f, nil
}

// Feedback is what Users said about the Findings of the Customer's
// Prioritization, oldest first.
func (t *Tx) Feedback(ctx context.Context, customer tenancy.CustomerID, prioritization uuid.UUID) ([]StoredFeedback, error) {
	rows, err := t.q.ListPrioritizationFeedback(ctx, sqlcgen.ListPrioritizationFeedbackParams{PrioritizationID: prioritization, CustomerID: uuid.UUID(customer)})
	if err != nil {
		return nil, fmt.Errorf("list feedback on prioritization %s: %w", prioritization, err)
	}
	feedback := make([]StoredFeedback, len(rows))
	for i, row := range rows {
		feedback[i] = StoredFeedback{
			ID:          row.ID,
			Finding:     row.FindingID,
			Author:      tenancy.UserID(row.AuthorID),
			Verdict:     assessment.Verdict(row.VerdictID),
			Note:        row.Note,
			ViaAnalista: row.ViaAnalista,
			Created:     row.CreatedAt,
		}
	}
	return feedback, nil
}
