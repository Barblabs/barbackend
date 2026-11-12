package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

// Dossier is all that an Agent knows about a Finding (ADR 0016).
type Dossier = assessment.Dossier

// Summary is a stored Prioritization without its Findings.
type Summary = postgres.PrioritizationSummary

// FeedbackVerdicts are the codes of the verdicts a User can give.
func FeedbackVerdicts() []string { return assessment.VerdictCodes() }

type Service struct {
	db   *postgres.DB
	crew *Crew

	onOrderFeedback func()
}

func NewService(db *postgres.DB, crew *Crew) *Service {
	return &Service{db: db, crew: crew}
}

// OnOrderFeedback has fn called after a User records that a Finding should be
// attended earlier or later, which places it again (ADR 0026). fn must return
// at once. It is meant to be set once, before the Service is used.
func (s *Service) OnOrderFeedback(fn func()) {
	s.onOrderFeedback = fn
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

// Get is one of the Customer's Prioritizations with the Dossier and state of
// each of its Findings, and the newest Action Plan and the Feedback of each,
// whichever Prioritization of the chain they were given on. It fails with
// ErrPrioritizationNotFound.
func (s *Service) Get(ctx context.Context, caller tenancy.User, id uuid.UUID) (Prioritization, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return Prioritization{}, err
	}
	var (
		p     Prioritization
		plans []postgres.StoredPlan
	)
	err = s.db.InTx(ctx, func(tx *postgres.Tx) error {
		stored, err := tx.Prioritization(ctx, customer, id)
		if err != nil {
			return err
		}
		if p, err = load(ctx, tx, customer, stored); err != nil {
			return err
		}
		if plans, err = tx.LatestPlans(ctx, customer, id); err != nil {
			return err
		}
		p.Feedback, err = tx.Feedback(ctx, customer, id)
		return err
	})
	if errors.Is(err, postgres.ErrNotFound) {
		return Prioritization{}, fmt.Errorf("%w: %w", ErrPrioritizationNotFound, err)
	}
	if err != nil {
		return Prioritization{}, err
	}
	p.Plans = make([]Plan, len(plans))
	for i, stored := range plans {
		if err := json.Unmarshal(stored.Content, &p.Plans[i]); err != nil {
			return Prioritization{}, fmt.Errorf("read plan %s: %w", stored.ID, err)
		}
		p.Plans[i].Finding, p.Plans[i].Created = stored.Finding.String(), stored.Created
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

// Plan runs Luna on a Finding of one of the Customer's Prioritizations, on its
// Dossier as it is now, and stores its Action Plan with that Dossier, so the
// plan can be traced to what Luna read. It holds no transaction
// while it runs. It fails with ErrPrioritizationNotFound or
// ErrFindingNotFound before calling the model, and with ErrRefused,
// ErrRejected or ErrUnavailable, storing nothing, when Luna has no verified
// answer.
func (s *Service) Plan(ctx context.Context, caller tenancy.User, id uuid.UUID, finding string) (Plan, error) {
	customer, err := caller.ActsFor()
	if err != nil {
		return Plan{}, err
	}
	findingID, err := parseFinding(finding)
	if err != nil {
		return Plan{}, err
	}
	d, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (assessment.Dossier, error) {
		if err := holdsFinding(ctx, tx, customer, id, findingID); err != nil {
			return assessment.Dossier{}, err
		}
		return dossierOfFinding(ctx, tx, customer, findingID)
	})
	if err != nil {
		return Plan{}, err
	}
	run, err := s.crew.Plan(ctx, d)
	if err != nil {
		return Plan{}, err
	}
	if run.Output == nil {
		return Plan{}, failure(run.Status, run.Violations)
	}
	plan := Plan{Finding: findingID.String(), Dossier: d, Luna: run}
	content, err := json.Marshal(plan)
	if err != nil {
		return Plan{}, fmt.Errorf("write plan of %s: %w", finding, err)
	}
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		plan.Created, err = tx.CreatePlan(ctx, customer, id, postgres.StoredPlan{ID: uuid.New(), Finding: findingID, Content: content})
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
	stored, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) (Feedback, error) {
		if err := holdsFinding(ctx, tx, customer, id, f.Finding); err != nil {
			return Feedback{}, err
		}
		return tx.AddFeedback(ctx, customer, id, f)
	})
	if err == nil && slices.Contains(orderVerdicts, f.Verdict) && s.onOrderFeedback != nil {
		s.onOrderFeedback()
	}
	return stored, err
}

func holdsFinding(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, id, finding uuid.UUID) error {
	holds, err := tx.PrioritizationHolds(ctx, customer, id, finding)
	if errors.Is(err, postgres.ErrNotFound) {
		return fmt.Errorf("%w: %w", ErrPrioritizationNotFound, err)
	}
	if err != nil {
		return err
	}
	if !holds {
		return fmt.Errorf("%w: %s", ErrFindingNotFound, finding)
	}
	return nil
}

// parseFinding reads a Finding's id, which only a stored Finding has. It
// fails with ErrFindingNotFound for any other text.
func parseFinding(finding string) (uuid.UUID, error) {
	id, err := uuid.Parse(strings.TrimSpace(finding))
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("%w: %q is not the id of a Finding", ErrFindingNotFound, finding)
	}
	return id, nil
}

func newFeedback(caller tenancy.User, finding, verdictCode, note string) (Feedback, error) {
	verdict, err := assessment.ParseVerdict(verdictCode)
	if err != nil {
		return Feedback{}, fmt.Errorf("%w: %w", ErrInvalidFeedback, err)
	}
	if utf8.RuneCountInString(note) > MaxNoteLength {
		return Feedback{}, fmt.Errorf("%w: note is longer than %d characters", ErrInvalidFeedback, MaxNoteLength)
	}
	id, err := parseFinding(finding)
	if err != nil {
		return Feedback{}, err
	}
	return Feedback{ID: uuid.New(), Finding: id, Author: caller.ID(), Verdict: verdict, Note: note}, nil
}
