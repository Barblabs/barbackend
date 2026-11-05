package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"barbackend/internal/assessment"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

const (
	DefaultLimit = 20
	MaxLimit     = 100

	// MaxNoteLength is in characters.
	MaxNoteLength = 2000
)

var (
	// ErrPrioritizationNotFound is a Prioritization the Customer does not have.
	ErrPrioritizationNotFound = errors.New("prioritization not found")
	// ErrInvalidFeedback is a verdict that is none, or too long a note.
	ErrInvalidFeedback = errors.New("invalid feedback")
	// ErrInvalidLimit is a page size out of range.
	ErrInvalidLimit = errors.New("invalid limit")
	// ErrRefused is a request the model's safety classifiers declined.
	ErrRefused = errors.New("the agent declined to answer")
	// ErrRejected is an Agent whose answers kept failing verification.
	ErrRejected = errors.New("the agent's answer failed verification")
	// ErrUnavailable is a model that could not be called or did not finish.
	ErrUnavailable = errors.New("the agent is unavailable")
)

// Feedback is what a User said about a Finding of a Prioritization.
type Feedback = postgres.StoredFeedback

// Summary is a stored Prioritization without its Findings.
type Summary = postgres.PrioritizationSummary

// FeedbackVerdicts are the codes of the verdicts a User can give.
func FeedbackVerdicts() []string { return assessment.VerdictCodes() }

type Service struct {
	db   *postgres.DB
	crew *Crew
}

func NewService(db *postgres.DB, crew *Crew) *Service {
	return &Service{db: db, crew: crew}
}

// Prioritize runs the Prioritizer on the Customer's open Findings and stores
// the Prioritization, holding no transaction while it runs. It fails as
// Crew.Prioritize does, and with ErrRefused, ErrRejected or ErrUnavailable,
// storing nothing, when the Prioritizer has no verified answer: the newest
// stored Prioritization stays the one to follow.
func (s *Service) Prioritize(ctx context.Context, customer tenancy.CustomerID, findings []assessment.Dossier) (Prioritization, error) {
	p, err := s.crew.Prioritize(ctx, findings)
	if err != nil {
		return Prioritization{}, err
	}
	if p.Prioritizer.Output == nil {
		return Prioritization{}, failure(p.Prioritizer.Status, p.Prioritizer.Violations)
	}
	content, err := json.Marshal(p)
	if err != nil {
		return Prioritization{}, fmt.Errorf("write prioritization: %w", err)
	}
	p.ID = uuid.New()
	stored := postgres.StoredPrioritization{ID: p.ID, Content: content, Findings: len(p.Findings), Groups: len(p.Prioritizer.Output.Groups)}
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		p.Created, err = tx.CreatePrioritization(ctx, customer, stored)
		return err
	})
	if err != nil {
		return Prioritization{}, err
	}
	return p, nil
}

func failure(status Status, violations []string) error {
	switch status {
	case Refused:
		return ErrRefused
	case Rejected:
		return fmt.Errorf("%w: %s", ErrRejected, strings.Join(violations, "; "))
	default:
		return ErrUnavailable
	}
}

// List is the Customer's Prioritizations, newest first. A zero limit takes
// DefaultLimit. It fails with ErrInvalidLimit.
func (s *Service) List(ctx context.Context, caller tenancy.User, limit int) ([]Summary, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return nil, err
	}
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return nil, fmt.Errorf("%w: must be a number from 1 to %d", ErrInvalidLimit, MaxLimit)
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]Summary, error) {
		return tx.ListPrioritizations(ctx, customer, limit)
	})
}

// Get is one of the Customer's Prioritizations with the newest Action Plan of
// each Finding that has one and its Feedback. It fails with
// ErrPrioritizationNotFound.
func (s *Service) Get(ctx context.Context, caller tenancy.User, id uuid.UUID) (Prioritization, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return Prioritization{}, err
	}
	var stored postgres.StoredPrioritization
	var plans []postgres.StoredPlan
	var feedback []Feedback
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		if stored, err = tx.Prioritization(ctx, customer, id); err != nil {
			return err
		}
		if plans, err = tx.LatestPlans(ctx, customer, id); err != nil {
			return err
		}
		feedback, err = tx.Feedback(ctx, customer, id)
		return err
	})
	if errors.Is(err, postgres.ErrNotFound) {
		return Prioritization{}, fmt.Errorf("%w: %w", ErrPrioritizationNotFound, err)
	}
	if err != nil {
		return Prioritization{}, err
	}
	p, err := restore(stored)
	if err != nil {
		return Prioritization{}, err
	}
	p.Feedback = feedback
	p.Plans = make([]Plan, len(plans))
	for i, stored := range plans {
		p.Plans[i] = Plan{Finding: stored.Finding, Created: stored.Created}
		if err := json.Unmarshal(stored.Content, &p.Plans[i].Luna); err != nil {
			return Prioritization{}, fmt.Errorf("read plan %s: %w", stored.ID, err)
		}
	}
	return p, nil
}

// Latest is the Customer's newest Prioritization, as Get. It fails with
// ErrPrioritizationNotFound when there is none.
func (s *Service) Latest(ctx context.Context, caller tenancy.User) (Prioritization, error) {
	newest, err := s.List(ctx, caller, 1)
	if err != nil {
		return Prioritization{}, err
	}
	if len(newest) == 0 {
		return Prioritization{}, ErrPrioritizationNotFound
	}
	return s.Get(ctx, caller, newest[0].ID)
}

// Plan runs Luna on a Finding of one of the Customer's Prioritizations and
// stores its Action Plan, holding no transaction while it runs. It fails with
// ErrPrioritizationNotFound or ErrFindingNotFound before calling the model,
// and with ErrRefused, ErrRejected or ErrUnavailable, storing nothing, when
// Luna has no verified answer.
func (s *Service) Plan(ctx context.Context, caller tenancy.User, id uuid.UUID, finding string) (Plan, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return Plan{}, err
	}
	stored, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (postgres.StoredPrioritization, error) {
		return tx.Prioritization(ctx, customer, id)
	})
	if errors.Is(err, postgres.ErrNotFound) {
		return Plan{}, fmt.Errorf("%w: %w", ErrPrioritizationNotFound, err)
	}
	if err != nil {
		return Plan{}, err
	}
	p, err := restore(stored)
	if err != nil {
		return Plan{}, err
	}
	finding = strings.TrimSpace(finding)
	run, err := s.crew.Plan(ctx, p, finding)
	if err != nil {
		return Plan{}, err
	}
	if run.Output == nil {
		return Plan{}, failure(run.Status, run.Violations)
	}
	content, err := json.Marshal(run)
	if err != nil {
		return Plan{}, fmt.Errorf("write plan of %s: %w", finding, err)
	}
	plan := Plan{Finding: finding, Luna: run}
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		plan.Created, err = tx.CreatePlan(ctx, customer, id, postgres.StoredPlan{ID: uuid.New(), Finding: finding, Content: content})
		return err
	})
	if err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// RecordFeedback stores a User's verdict, by its code, on a Finding of one of
// the Customer's Prioritizations. It fails with ErrInvalidFeedback,
// ErrPrioritizationNotFound or ErrFindingNotFound.
func (s *Service) RecordFeedback(ctx context.Context, caller tenancy.User, id uuid.UUID, finding, verdictCode, note string) (Feedback, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return Feedback{}, err
	}
	f, err := newFeedback(caller, finding, verdictCode, note)
	if err != nil {
		return Feedback{}, err
	}
	return postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (Feedback, error) {
		if err := holdsFinding(ctx, tx, customer, id, f.Finding); err != nil {
			return Feedback{}, err
		}
		return tx.AddFeedback(ctx, customer, id, f)
	})
}

func holdsFinding(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, id uuid.UUID, finding string) error {
	holds, err := tx.PrioritizationHolds(ctx, customer, id, finding)
	if errors.Is(err, postgres.ErrNotFound) {
		return fmt.Errorf("%w: %w", ErrPrioritizationNotFound, err)
	}
	if err != nil {
		return err
	}
	if !holds {
		return fmt.Errorf("%w: %q", ErrFindingNotFound, finding)
	}
	return nil
}

func newFeedback(caller tenancy.User, finding, verdictCode, note string) (Feedback, error) {
	verdict, err := assessment.ParseVerdict(verdictCode)
	if err != nil {
		return Feedback{}, fmt.Errorf("%w: %w", ErrInvalidFeedback, err)
	}
	if utf8.RuneCountInString(note) > MaxNoteLength {
		return Feedback{}, fmt.Errorf("%w: note is longer than %d characters", ErrInvalidFeedback, MaxNoteLength)
	}
	return Feedback{ID: uuid.New(), Finding: strings.TrimSpace(finding), Author: caller.ID(), Verdict: verdict, Note: note}, nil
}

func restore(stored postgres.StoredPrioritization) (Prioritization, error) {
	p := Prioritization{ID: stored.ID, Created: stored.Created}
	if err := json.Unmarshal(stored.Content, &p); err != nil {
		return Prioritization{}, fmt.Errorf("read prioritization %s: %w", stored.ID, err)
	}
	return p, nil
}
