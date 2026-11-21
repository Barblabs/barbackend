package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"barbackend/internal/assessment"
	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

// HistoryEntry is one change of a Finding's place in the Customer's order
// (ADR 0036). CloseReason is, for the newest entry when it is a Left one and
// the Finding is still closed, why it closed; empty otherwise.
type HistoryEntry struct {
	assessment.HistoryEntry
	CloseReason string
}

// FindingHistory is how the Customer's order placed the Finding of that id,
// newest change first, computed from what the Prioritizations stored and
// calling no Agent (ADR 0036). A Finding no Prioritization held has none. It
// fails with ErrFindingNotFound when the Customer has no such Finding.
func (s *Service) FindingHistory(ctx context.Context, caller tenancy.User, id string) ([]HistoryEntry, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	findingID, err := parseFinding(id)
	if err != nil {
		return nil, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]HistoryEntry, error) {
		return history(ctx, tx, customer, findingID)
	})
}

func history(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, id uuid.UUID) ([]HistoryEntry, error) {
	state, err := tx.FindingCloseOfCustomer(ctx, customer, finding.ID(id))
	if errors.Is(err, postgres.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrFindingNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	stored, err := tx.FindingVersions(ctx, customer, id)
	if err != nil {
		return nil, err
	}
	versions := make([]assessment.Version, len(stored))
	for i, v := range stored {
		versions[i] = historyVersion(v)
	}
	prioritizations, placements := assessment.HistoryReads(versions)
	lists, err := historyLists(ctx, tx, customer, prioritizations)
	if err != nil {
		return nil, err
	}
	dossiers, err := historyDossiers(ctx, tx, customer, id, placements)
	if err != nil {
		return nil, err
	}
	feedback, err := tx.FeedbackOnFinding(ctx, customer, id)
	if err != nil {
		return nil, err
	}
	var direct []assessment.TimedFeedback
	for _, f := range feedback {
		if !f.ViaAnalista && slices.Contains(orderVerdicts, f.Verdict) {
			direct = append(direct, assessment.TimedFeedback{At: f.Created, Verdict: f.Verdict.Code(), Note: f.Note})
		}
	}
	entries := assessment.History(id.String(), versions, lists, dossiers, direct)
	out := make([]HistoryEntry, len(entries))
	for i, e := range entries {
		out[i] = HistoryEntry{HistoryEntry: e}
	}
	if len(out) > 0 && out[0].Kind == assessment.Left && state.Closed {
		out[0].CloseReason = state.Reason.String()
	}
	return out, nil
}

func historyVersion(v postgres.FindingVersion) assessment.Version {
	out := assessment.Version{Prioritization: v.Prioritization.String(), Created: v.Created}
	if v.BusinessContext > 0 {
		out.ContextVersion = &v.BusinessContext
	}
	if p := v.Place; p != nil {
		out.Slot = &assessment.Slot{Placement: p.Placement.String(), PlacedAt: p.Placed, Group: p.Group, ScoreRank: p.ScoreRank}
	}
	return out
}

func historyLists(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, ids []string) (map[string]assessment.PriorityList, error) {
	contents, err := tx.PrioritizationContents(ctx, customer, uuids(ids))
	if err != nil {
		return nil, err
	}
	out := make(map[string]assessment.PriorityList, len(contents))
	for id, raw := range contents {
		var c content
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("read prioritization %s: %w", id, err)
		}
		out[id.String()] = c.List
	}
	return out, nil
}

func historyDossiers(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, finding uuid.UUID, ids []string) (map[string]assessment.Dossier, error) {
	raw, err := tx.PlacementDossiers(ctx, customer, finding, uuids(ids))
	if err != nil {
		return nil, err
	}
	out := make(map[string]assessment.Dossier, len(raw))
	for id, r := range raw {
		var d assessment.Dossier
		if err := json.Unmarshal(r, &d); err != nil {
			return nil, fmt.Errorf("read the dossier of placement %s: %w", id, err)
		}
		out[id.String()] = d
	}
	return out, nil
}

// uuids are ids that assessment had as strings, which came from uuids.
func uuids(ids []string) []uuid.UUID {
	out := make([]uuid.UUID, len(ids))
	for i, id := range ids {
		out[i] = uuid.MustParse(id)
	}
	return out
}
