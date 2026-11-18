package agents

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"

	"barbackend/internal/assessment"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

const (
	// maxPlanAttempts is how many times Luna, on her own, tries the Action
	// Plan of a Finding as one placement of it before she leaves it to a
	// User's request (ADR 0034).
	maxPlanAttempts = 3
	// planBatch is how many Action Plans Luna writes for one Customer before
	// the next Customer's turn, and before she reads again what is due.
	planBatch = 20
)

// PlanningRun is what one run of Luna on her own did.
type PlanningRun struct {
	Planned int `json:"planned"`
	Failed  int `json:"failed"`
}

// duePlan is an Action Plan Luna is to write: of the Finding of dossier, as
// it is now, on a Prioritization that places it with placement.
type duePlan struct {
	prioritization uuid.UUID
	placement      uuid.UUID
	dossier        assessment.Dossier
}

// PlanAll has Luna write, on her own, the Action Plan of each open Finding of
// the newest Prioritization of every Customer that is not deactivated, when
// it has none or it changed since its newest one as a round would place it
// again (ADR 0034). She writes them one at a time, in the order of the
// Prioritization, planBatch for one Customer before the next one's turn, and
// each Finding at most once a run. No transaction is held while she runs.
//
// A rejected or refused answer is a failed attempt of that placement of the
// Finding, tried again in a later run up to maxPlanAttempts times. A model
// that cannot be called stops the run with ErrUnavailable and spends no
// attempt. A Customer whose plans cannot be read is logged and left until the
// next run.
func (s *Service) PlanAll(ctx context.Context) (PlanningRun, error) {
	var run PlanningRun
	pending, err := s.activeCustomers(ctx)
	if err != nil {
		return run, err
	}
	tried := map[string]bool{}
	var stop error
	for len(pending) > 0 && stop == nil {
		pending = slices.DeleteFunc(pending, func(customer tenancy.CustomerID) bool {
			if stop != nil {
				return true
			}
			more, err := s.planNext(ctx, customer, tried, &run)
			switch {
			case ctx.Err() != nil || errors.Is(err, ErrUnavailable):
				stop = cmp.Or(ctx.Err(), err)
			case err != nil:
				log.Printf("agents: luna: customer %s: %v", customer, err)
			}
			return err != nil || !more
		})
	}
	if run != (PlanningRun{}) {
		log.Printf("agents: luna: planned %d, failed %d", run.Planned, run.Failed)
	}
	return run, stop
}

// planNext writes the Customer's next planBatch due Action Plans that this
// run has not tried, and reports whether there were any.
func (s *Service) planNext(ctx context.Context, customer tenancy.CustomerID, tried map[string]bool, run *PlanningRun) (bool, error) {
	due, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]duePlan, error) {
		return duePlans(ctx, tx, customer, tried)
	})
	if err != nil || len(due) == 0 {
		return false, err
	}
	for _, d := range due {
		tried[d.dossier.Finding] = true
		if err := s.planOnOwn(ctx, customer, d, run); err != nil {
			return false, err
		}
	}
	return true, nil
}

// duePlans is up to planBatch Action Plans due on the Customer's newest
// Prioritization, in its order, leaving out the Findings in tried.
func duePlans(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, tried map[string]bool) ([]duePlan, error) {
	newest, err := tx.NewestPrioritization(ctx, customer)
	if errors.Is(err, postgres.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	placed, err := tx.PrioritizationFindings(ctx, customer, newest.ID)
	if err != nil {
		return nil, err
	}
	open, err := openByFinding(ctx, tx, customer)
	if err != nil {
		return nil, err
	}
	planned, err := plannedDossiers(ctx, tx, customer, newest.ID)
	if err != nil {
		return nil, err
	}
	failures, err := tx.PlanFailures(ctx, customer, newest.ID)
	if err != nil {
		return nil, err
	}
	var due []duePlan
	for _, f := range placed {
		id := f.Finding.String()
		now, isOpen := open[id]
		if !isOpen || tried[id] || failures[f.Finding] >= maxPlanAttempts {
			continue
		}
		if was, ok := planned[id]; ok && !assessment.Changed(was, now) {
			continue
		}
		due = append(due, duePlan{prioritization: newest.ID, placement: f.Placement, dossier: now})
		if len(due) == planBatch {
			break
		}
	}
	return due, nil
}

// openByFinding is the Dossier, as it is now, of each open Finding of the
// Customer that has a Score, by Finding.
func openByFinding(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID) (map[string]assessment.Dossier, error) {
	bc, err := tx.BusinessContext(ctx, customer)
	if err != nil {
		return nil, err
	}
	dossiers, _, err := openDossiers(ctx, tx, customer, bc.Context)
	if err != nil {
		return nil, err
	}
	open := make(map[string]assessment.Dossier, len(dossiers))
	for _, d := range dossiers {
		open[d.Finding] = d
	}
	return open, nil
}

// plannedDossiers is, by Finding of the Customer's Prioritization that has
// an Action Plan, the Dossier its newest one was written from.
func plannedDossiers(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, prioritization uuid.UUID) (map[string]assessment.Dossier, error) {
	stored, err := tx.LatestPlans(ctx, customer, prioritization)
	if err != nil {
		return nil, err
	}
	plans, err := restorePlans(stored)
	if err != nil {
		return nil, err
	}
	planned := make(map[string]assessment.Dossier, len(plans))
	for _, p := range plans {
		planned[p.Finding] = p.Dossier
	}
	return planned, nil
}

// planOnOwn runs Luna on d and stores her Action Plan, or counts a failed
// attempt of its placement when she has no verified answer.
func (s *Service) planOnOwn(ctx context.Context, customer tenancy.CustomerID, d duePlan, run *PlanningRun) error {
	luna, err := s.crew.Plan(ctx, d.dossier)
	if err != nil {
		return err
	}
	// A run stopped on shutdown is not the Finding's failure.
	if err := ctx.Err(); err != nil {
		return err
	}
	switch luna.Status {
	case Verified:
		if _, err := s.storePlan(ctx, customer, d.prioritization, d.dossier, luna); err != nil {
			return err
		}
		run.Planned++
		return nil
	case Failed:
		return fmt.Errorf("plan %s: %w", d.dossier.Finding, ErrUnavailable)
	default:
		log.Printf("agents: luna: finding %s %s: %q", d.dossier.Finding, luna.Status, luna.Violations)
		err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
			return tx.RecordPlanFailure(ctx, d.placement)
		})
		if err != nil {
			return err
		}
		run.Failed++
		return nil
	}
}

// storePlan stores luna, a verified run on d, as the Action Plan of its
// Finding on the Customer's Prioritization, with d, so the plan can be traced
// to what Luna read.
func (s *Service) storePlan(ctx context.Context, customer tenancy.CustomerID, prioritization uuid.UUID, d assessment.Dossier, luna Run[assessment.ActionPlan]) (Plan, error) {
	finding, err := parseFinding(d.Finding)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Finding: d.Finding, Dossier: d, Luna: luna}
	content, err := json.Marshal(plan)
	if err != nil {
		return Plan{}, fmt.Errorf("write plan of %s: %w", d.Finding, err)
	}
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		plan.Created, err = tx.CreatePlan(ctx, customer, prioritization, postgres.StoredPlan{ID: uuid.New(), Finding: finding, Content: content})
		return err
	})
	if err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// restorePlans reads stored Action Plans.
func restorePlans(stored []postgres.StoredPlan) ([]Plan, error) {
	plans := make([]Plan, len(stored))
	for i, p := range stored {
		if err := json.Unmarshal(p.Content, &plans[i]); err != nil {
			return nil, fmt.Errorf("read plan %s: %w", p.ID, err)
		}
		plans[i].Finding, plans[i].Created = p.Finding.String(), p.Created
	}
	return plans, nil
}

// activeCustomers is every Customer that is not deactivated.
func (s *Service) activeCustomers(ctx context.Context) ([]tenancy.CustomerID, error) {
	customers, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]postgres.StoredCustomer, error) {
		return tx.Customers(ctx)
	})
	if err != nil {
		return nil, err
	}
	var active []tenancy.CustomerID
	for _, c := range customers {
		if c.Deactivated.IsZero() {
			active = append(active, c.Customer.ID())
		}
	}
	return active, nil
}
