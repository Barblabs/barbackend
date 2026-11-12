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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Constraints that keep a Customer's Prioritizations one chain (ADR 0026).
const (
	prioritizationPreviousKey = "prioritizations_previous_id_key"
	prioritizationFirstIndex  = "prioritizations_first_idx"
)

// StoredPrioritization is a Prioritization as the database records it: its
// content is opaque here.
type StoredPrioritization struct {
	ID uuid.UUID
	// Previous is the Prioritization it was built from, nil for a Customer's
	// first.
	Previous *uuid.UUID
	// BusinessContext is the version of the Business Context its Prioritizer
	// read, 0 when the Customer had none.
	BusinessContext int
	Content         json.RawMessage
	Findings        int
	Groups          int
	Created         time.Time
}

// PrioritizationSummary is a stored Prioritization without its content.
type PrioritizationSummary struct {
	ID       uuid.UUID
	Findings int
	Groups   int
	Created  time.Time
}

// Placement is where a Prioritization puts one of its Findings.
type Placement struct {
	Finding uuid.UUID
	// Group is the position of its Priority Group, from 1.
	Group int
	// ScoreRank is where its Score alone would put it, 1 the highest.
	ScoreRank int
	// Kept is the placement of an earlier Prioritization of the chain that
	// the Finding keeps, uuid.Nil when this one places it.
	Kept uuid.UUID
	// Dossier is what the Prioritizer read of a Finding this one places,
	// opaque here.
	Dossier json.RawMessage
}

// PlacedFinding is a Finding of a stored Prioritization.
type PlacedFinding struct {
	Finding uuid.UUID
	// Placement identifies when and how the chain last placed it: Placed is
	// when that round read what it placed, and Dossier what it read.
	Placement uuid.UUID
	Placed    time.Time
	Dossier   json.RawMessage
	// Closed is when the Finding was closed, nil while it is open.
	Closed *time.Time
}

// TransactionTime is when the transaction began, as Postgres tells it.
func (t *Tx) TransactionTime(ctx context.Context) (time.Time, error) {
	now, err := t.q.TransactionTime(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("read the transaction time: %w", err)
	}
	return now, nil
}

// CreatePrioritization stores p with the place of each of its Findings, and
// the placements of those it places, read at placed, and returns when it was
// created. It fails with ErrNotNewest when p.Previous is no longer the
// Customer's newest Prioritization, or p is a first one and the Customer
// already has one.
func (t *Tx) CreatePrioritization(ctx context.Context, customer tenancy.CustomerID, p StoredPrioritization, placed time.Time, placements []Placement) (time.Time, error) {
	params := sqlcgen.InsertPrioritizationParams{
		ID:           p.ID,
		CustomerID:   uuid.UUID(customer),
		FindingCount: int32(p.Findings),
		GroupCount:   int32(p.Groups),
		Content:      p.Content,
	}
	if p.Previous != nil {
		params.PreviousID = pgtype.UUID{Bytes: *p.Previous, Valid: true}
	}
	if p.BusinessContext > 0 {
		params.BusinessContextVersion = ptr(int32(p.BusinessContext))
	}
	created, err := t.q.InsertPrioritization(ctx, params)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && (pgErr.ConstraintName == prioritizationPreviousKey || pgErr.ConstraintName == prioritizationFirstIndex) {
		return time.Time{}, fmt.Errorf("insert prioritization %s: %w", p.ID, ErrNotNewest)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("insert prioritization %s: %w", p.ID, err)
	}
	var placedNow []sqlcgen.InsertFindingPlacementsParams
	rows := make([]sqlcgen.InsertPrioritizationFindingsParams, len(placements))
	for i, pl := range placements {
		placement := pl.Kept
		if placement == uuid.Nil {
			placement = uuid.New()
			placedNow = append(placedNow, sqlcgen.InsertFindingPlacementsParams{ID: placement, FindingID: pl.Finding, PlacedAt: placed, Dossier: pl.Dossier})
		}
		rows[i] = sqlcgen.InsertPrioritizationFindingsParams{
			PrioritizationID: p.ID, FindingID: pl.Finding, PlacementID: placement, GroupPosition: int32(pl.Group), ScoreRank: int32(pl.ScoreRank),
		}
	}
	if _, err := t.q.InsertFindingPlacements(ctx, placedNow); err != nil {
		return time.Time{}, fmt.Errorf("insert the placements of prioritization %s: %w", p.ID, err)
	}
	if _, err := t.q.InsertPrioritizationFindings(ctx, rows); err != nil {
		return time.Time{}, fmt.Errorf("insert the findings of prioritization %s: %w", p.ID, err)
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
	return restorePrioritization(sqlcgen.GetNewestPrioritizationRow(row)), nil
}

// NewestPrioritization is the Customer's Prioritization that no other was
// built from. It fails with ErrNotFound when the Customer has none.
func (t *Tx) NewestPrioritization(ctx context.Context, customer tenancy.CustomerID) (StoredPrioritization, error) {
	row, err := t.q.GetNewestPrioritization(ctx, uuid.UUID(customer))
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredPrioritization{}, fmt.Errorf("newest prioritization of customer %s: %w", customer, ErrNotFound)
	}
	if err != nil {
		return StoredPrioritization{}, fmt.Errorf("get newest prioritization of customer %s: %w", customer, err)
	}
	return restorePrioritization(row), nil
}

func restorePrioritization(row sqlcgen.GetNewestPrioritizationRow) StoredPrioritization {
	p := StoredPrioritization{ID: row.ID, Content: row.Content, Created: row.CreatedAt, BusinessContext: int(valueOrZero(row.BusinessContextVersion))}
	if row.PreviousID.Valid {
		previous := uuid.UUID(row.PreviousID.Bytes)
		p.Previous = &previous
	}
	return p
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

// PrioritizationFindings is the Findings of the Customer's Prioritization
// with their placements, in the order it puts them.
func (t *Tx) PrioritizationFindings(ctx context.Context, customer tenancy.CustomerID, id uuid.UUID) ([]PlacedFinding, error) {
	rows, err := t.q.ListPrioritizationFindings(ctx, sqlcgen.ListPrioritizationFindingsParams{PrioritizationID: id, CustomerID: uuid.UUID(customer)})
	if err != nil {
		return nil, fmt.Errorf("list the findings of prioritization %s: %w", id, err)
	}
	out := make([]PlacedFinding, len(rows))
	for i, row := range rows {
		out[i] = PlacedFinding{Finding: row.FindingID, Placement: row.PlacementID, Placed: row.PlacedAt, Dossier: row.Dossier, Closed: row.ClosedAt}
	}
	return out, nil
}

// PrioritizationHolds is whether the Customer's Prioritization holds the
// Finding of that id. It fails with ErrNotFound when the Customer has no such
// Prioritization.
func (t *Tx) PrioritizationHolds(ctx context.Context, customer tenancy.CustomerID, id, finding uuid.UUID) (bool, error) {
	holds, err := t.q.PrioritizationHolds(ctx, sqlcgen.PrioritizationHoldsParams{FindingID: finding, ID: id, CustomerID: uuid.UUID(customer)})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("prioritization %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return false, fmt.Errorf("find finding %s in prioritization %s: %w", finding, id, err)
	}
	return holds, nil
}

// StoredPlan is an Action Plan for a Finding of a Prioritization: its content
// is opaque here.
type StoredPlan struct {
	ID      uuid.UUID
	Finding uuid.UUID
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
		return time.Time{}, fmt.Errorf("insert plan of %s in prioritization %s: %w", p.Finding, prioritization, err)
	}
	return created, nil
}

// LatestPlans are the newest Action Plan of each Finding of the Customer's
// Prioritization that has one, whichever Prioritization of the chain it was
// asked from.
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
	Finding     uuid.UUID
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
// Prioritization, whichever Prioritization of the chain they said it on,
// oldest first.
func (t *Tx) Feedback(ctx context.Context, customer tenancy.CustomerID, prioritization uuid.UUID) ([]StoredFeedback, error) {
	rows, err := t.q.ListPrioritizationFeedback(ctx, sqlcgen.ListPrioritizationFeedbackParams{PrioritizationID: prioritization, CustomerID: uuid.UUID(customer)})
	if err != nil {
		return nil, fmt.Errorf("list feedback on prioritization %s: %w", prioritization, err)
	}
	feedback := make([]StoredFeedback, len(rows))
	for i, row := range rows {
		feedback[i] = restoreFeedback(row)
	}
	return feedback, nil
}

func restoreFeedback(row sqlcgen.ListPrioritizationFeedbackRow) StoredFeedback {
	return StoredFeedback{
		ID:          row.ID,
		Finding:     row.FindingID,
		Author:      tenancy.UserID(row.AuthorID),
		Verdict:     assessment.Verdict(row.VerdictID),
		Note:        row.Note,
		ViaAnalista: row.ViaAnalista,
		Created:     row.CreatedAt,
	}
}

// ConversationOwner is who a conversation with the Analista belongs to.
type ConversationOwner struct {
	Customer tenancy.CustomerID
	User     tenancy.UserID
}

// StoredConversation is a conversation with the Analista at one turn.
type StoredConversation struct {
	History json.RawMessage
	Turns   int
}

// CreateConversation stores the first turn of a conversation.
func (t *Tx) CreateConversation(ctx context.Context, owner ConversationOwner, id uuid.UUID, history json.RawMessage) error {
	err := t.q.InsertAnalistaConversation(ctx, sqlcgen.InsertAnalistaConversationParams{
		ID:         id,
		CustomerID: uuid.UUID(owner.Customer),
		UserID:     uuid.UUID(owner.User),
		History:    history,
	})
	if err != nil {
		return fmt.Errorf("insert conversation %s: %w", id, err)
	}
	return nil
}

// ClaimConversation marks the conversation as answering a message and returns
// it. It fails with ErrNotFound unless owner has it, and with
// ErrConversationClaimed while a claim younger than lifetime holds it.
func (t *Tx) ClaimConversation(ctx context.Context, owner ConversationOwner, id uuid.UUID, lifetime time.Duration) (StoredConversation, error) {
	row, err := t.q.ClaimAnalistaConversation(ctx, sqlcgen.ClaimAnalistaConversationParams{
		ID:              id,
		CustomerID:      uuid.UUID(owner.Customer),
		UserID:          uuid.UUID(owner.User),
		LifetimeSeconds: lifetime.Seconds(),
	})
	if err == nil {
		return StoredConversation{History: row.History, Turns: int(row.Turns)}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return StoredConversation{}, fmt.Errorf("claim conversation %s: %w", id, err)
	}
	exists, err := t.q.AnalistaConversationExists(ctx, sqlcgen.AnalistaConversationExistsParams{ID: id, CustomerID: uuid.UUID(owner.Customer), UserID: uuid.UUID(owner.User)})
	if err != nil {
		return StoredConversation{}, fmt.Errorf("find conversation %s: %w", id, err)
	}
	if exists {
		return StoredConversation{}, fmt.Errorf("conversation %s: %w", id, ErrConversationClaimed)
	}
	return StoredConversation{}, fmt.Errorf("conversation %s: %w", id, ErrNotFound)
}

// ReleaseConversation lifts the claim taken at turns, leaving the history.
func (t *Tx) ReleaseConversation(ctx context.Context, owner ConversationOwner, id uuid.UUID, turns int) error {
	err := t.q.ReleaseAnalistaConversation(ctx, sqlcgen.ReleaseAnalistaConversationParams{ID: id, CustomerID: uuid.UUID(owner.Customer), UserID: uuid.UUID(owner.User), Turns: int32(turns)})
	if err != nil {
		return fmt.Errorf("release conversation %s: %w", id, err)
	}
	return nil
}

// AdvanceConversation replaces the history with one a turn longer and lifts
// the claim. It fails with ErrConversationClaimed when the conversation is no
// longer at turns, because a stale claim was overtaken.
func (t *Tx) AdvanceConversation(ctx context.Context, owner ConversationOwner, id uuid.UUID, turns int, history json.RawMessage) error {
	updated, err := t.q.AdvanceAnalistaConversation(ctx, sqlcgen.AdvanceAnalistaConversationParams{
		ID:         id,
		CustomerID: uuid.UUID(owner.Customer),
		UserID:     uuid.UUID(owner.User),
		Turns:      int32(turns),
		History:    history,
	})
	if err != nil {
		return fmt.Errorf("advance conversation %s: %w", id, err)
	}
	if updated == 0 {
		return fmt.Errorf("conversation %s: %w", id, ErrConversationClaimed)
	}
	return nil
}
