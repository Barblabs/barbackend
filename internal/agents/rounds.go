package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"

	"barbackend/internal/assessment"
	"barbackend/internal/business"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/TcM1911/stix2"
	"github.com/google/uuid"
)

// maxRounds bounds the rounds one run makes for a Customer: enough to place
// 5,000 Findings, MaxFindings at a time, and never a loop that keeps paying.
// What is left waits for the next run.
const maxRounds = 50

// orderVerdicts are the verdicts that say where a Finding should be, which
// have it placed again when a User gives them directly (ADR 0026).
var orderVerdicts = []assessment.Verdict{assessment.VerdictShouldBeEarlier, assessment.VerdictShouldBeLater}

// content is what a stored Prioritization keeps beside its placements.
type content struct {
	List        assessment.PriorityList   `json:"list"`
	Prioritizer Run[assessment.Placement] `json:"prioritizer"`
}

// Prioritize brings the Customer's newest Prioritization up to date (ADR
// 0026), in as many rounds as it takes, up to maxRounds. Each round places,
// MaxFindings at a time, the open Findings that have no place yet and those
// that changed since they were placed, and every other open Finding keeps its
// place; a closed one leaves the order. When the Customer's Business Context
// changed since the newest Prioritization, the first round orders every open
// Finding anew. Each round stores a Prioritization built from the one before,
// holding no transaction while the Prioritizer runs.
//
// It reports how many Prioritizations it stored. It fails with ErrRefused,
// ErrRejected or ErrUnavailable when a round has no verified answer, and with
// postgres.ErrNotNewest when another round stored one first: the newest
// stored Prioritization stays the one to follow.
func (s *Service) Prioritize(ctx context.Context, customer tenancy.CustomerID) (int, error) {
	stored := 0
	for range maxRounds {
		placed, err := s.round(ctx, customer)
		if err != nil || !placed {
			return stored, err
		}
		stored++
	}
	return stored, nil
}

// PrioritizeAll runs the rounds every Customer that is not deactivated needs,
// one round per Customer in turn, so one with many Findings to place does not
// keep the others waiting. A Customer whose round fails is logged and left
// until the next run. Only a cancelled context stops it.
func (s *Service) PrioritizeAll(ctx context.Context) error {
	customers, err := postgres.InTxValue(ctx, s.db, func(tx *postgres.Tx) ([]postgres.StoredCustomer, error) {
		return tx.Customers(ctx)
	})
	if err != nil {
		return err
	}
	var pending []tenancy.CustomerID
	for _, c := range customers {
		if c.Deactivated.IsZero() {
			pending = append(pending, c.Customer.ID())
		}
	}
	for range maxRounds {
		pending = slices.DeleteFunc(pending, func(customer tenancy.CustomerID) bool {
			if ctx.Err() != nil {
				return true
			}
			placed, err := s.round(ctx, customer)
			if err != nil && ctx.Err() == nil {
				log.Printf("agents: prioritizer: customer %s: %v", customer, err)
			}
			return err != nil || !placed
		})
		if len(pending) == 0 {
			break
		}
	}
	return ctx.Err()
}

// round runs the Customer's next round, and reports whether it had anything
// to place.
func (s *Service) round(ctx context.Context, customer tenancy.CustomerID) (bool, error) {
	r, err := s.nextRound(ctx, customer)
	if err != nil || len(r.Findings) == 0 {
		return false, err
	}
	p, err := s.crew.Prioritize(ctx, r)
	if err != nil {
		return false, err
	}
	if p.Prioritizer.Output == nil {
		return false, failure(p.Prioritizer.Status, p.Prioritizer.Violations)
	}
	if err := s.store(ctx, customer, r, p); err != nil {
		return false, err
	}
	log.Printf("agents: prioritizer: customer %s: placed %d findings", customer, len(r.Findings))
	return true, nil
}

// nextRound reads what the Customer's next round places. A Round with no
// Findings has nothing to place.
func (s *Service) nextRound(ctx context.Context, customer tenancy.CustomerID) (Round, error) {
	var (
		r      Round
		newest *Prioritization
		open   []assessment.Dossier
	)
	err := s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		if r.read, err = tx.TransactionTime(ctx); err != nil {
			return err
		}
		bc, err := tx.BusinessContext(ctx, customer)
		if err != nil {
			return err
		}
		r.Context, r.ContextVersion = bc.Context, bc.Version
		if newest, err = newestOf(ctx, tx, customer); err != nil {
			return err
		}
		open, err = openDossiers(ctx, tx, customer, bc.Context)
		return err
	})
	if err != nil {
		return Round{}, err
	}
	var order assessment.Order
	if newest != nil {
		r.Previous = &newest.ID
		r.Feedback = orderFeedback(*newest)
		if newest.BusinessContext == r.ContextVersion {
			order = newest.order()
		}
	}
	plan := assessment.PlanRound(order, open, r.Feedback, MaxFindings)
	r.Standing, r.Placed, r.Findings = plan.Standing, plan.Placed, plan.Findings
	if newest != nil {
		r.kept = make(map[string]uuid.UUID, len(r.Placed))
		for _, d := range r.Placed {
			r.kept[d.Finding] = newest.States[d.Finding].placement
		}
	}
	return r, nil
}

// newestOf is the Customer's newest Prioritization, with its Findings and
// what Users said of them, or nil for a Customer with none.
func newestOf(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID) (*Prioritization, error) {
	stored, err := tx.NewestPrioritization(ctx, customer)
	if errors.Is(err, postgres.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p, err := load(ctx, tx, customer, stored)
	if err != nil {
		return nil, err
	}
	if p.Feedback, err = tx.Feedback(ctx, customer, p.ID); err != nil {
		return nil, err
	}
	return &p, nil
}

// load is a stored Prioritization with the Dossier and state of each of its
// Findings.
func load(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, stored postgres.StoredPrioritization) (Prioritization, error) {
	p := Prioritization{ID: stored.ID, Created: stored.Created, Previous: stored.Previous, BusinessContext: stored.BusinessContext}
	var c content
	if err := json.Unmarshal(stored.Content, &c); err != nil {
		return Prioritization{}, fmt.Errorf("read prioritization %s: %w", stored.ID, err)
	}
	p.List, p.Prioritizer = c.List, c.Prioritizer
	placed, err := tx.PrioritizationFindings(ctx, customer, stored.ID)
	if err != nil {
		return Prioritization{}, err
	}
	p.Findings = make([]assessment.Dossier, len(placed))
	p.States = make(map[string]FindingState, len(placed))
	for i, f := range placed {
		if err := json.Unmarshal(f.Dossier, &p.Findings[i]); err != nil {
			return Prioritization{}, fmt.Errorf("read the dossier of %s in prioritization %s: %w", f.Finding, stored.ID, err)
		}
		p.States[f.Finding.String()] = FindingState{Placed: f.Placed, Closed: f.Closed, placement: f.Placement}
	}
	return p, nil
}

// order is p as the order the next round starts from.
func (p Prioritization) order() assessment.Order {
	o := assessment.Order{List: p.List, Placed: make(map[string]assessment.Dossier, len(p.Findings)), Closed: map[string]bool{}}
	for _, d := range p.Findings {
		o.Placed[d.Finding] = d
		o.Closed[d.Finding] = p.States[d.Finding].Closed != nil
	}
	return o
}

// orderFeedback is, by Finding of p, the verdicts on where it should be that
// a User gave directly since the chain last placed it. Those the Analista
// recorded are left out: a conversation can be steered by text a Feed wrote,
// so they change no order (ADR 0016).
func orderFeedback(p Prioritization) map[string][]assessment.OrderFeedback {
	out := map[string][]assessment.OrderFeedback{}
	for _, f := range p.Feedback {
		id := f.Finding.String()
		if f.ViaAnalista || !slices.Contains(orderVerdicts, f.Verdict) || !f.Created.After(p.States[id].Placed) {
			continue
		}
		out[id] = append(out[id], assessment.OrderFeedback{Verdict: f.Verdict.Code(), Note: f.Note})
	}
	return out
}

// store stores p, the Prioritization r made, with the place of each of its
// Findings: those that stand keep their placements, and those r placed get
// one with their Dossiers, read when r read them.
func (s *Service) store(ctx context.Context, customer tenancy.CustomerID, r Round, p Prioritization) error {
	raw, err := json.Marshal(content{List: p.List, Prioritizer: p.Prioritizer})
	if err != nil {
		return fmt.Errorf("write prioritization: %w", err)
	}
	ranks := p.ScoreRanks()
	var placements []postgres.Placement
	for i, g := range p.List.Groups {
		for _, id := range g.Findings() {
			placement, err := s.placementOf(p, id, ranks[id], i+1, r.kept)
			if err != nil {
				return err
			}
			placements = append(placements, placement)
		}
	}
	stored := postgres.StoredPrioritization{
		ID: uuid.New(), Previous: p.Previous, BusinessContext: p.BusinessContext,
		Content: raw, Findings: len(p.Findings), Groups: len(p.List.Groups),
	}
	return s.db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.CreatePrioritization(ctx, customer, stored, r.read, placements)
		return err
	})
}

func (s *Service) placementOf(p Prioritization, id string, rank, group int, kept map[string]uuid.UUID) (postgres.Placement, error) {
	finding, err := uuid.Parse(id)
	if err != nil {
		return postgres.Placement{}, fmt.Errorf("%w: finding %q is not a stored Finding", ErrInvalidFindings, id)
	}
	placement := postgres.Placement{Finding: finding, Group: group, ScoreRank: rank, Kept: kept[id]}
	if placement.Kept != uuid.Nil {
		return placement, nil
	}
	d, _ := p.Finding(id)
	if placement.Dossier, err = json.Marshal(d); err != nil {
		return postgres.Placement{}, fmt.Errorf("write the dossier of %s: %w", id, err)
	}
	return placement, nil
}

// openDossiers builds the Dossier of each open Finding of the Customer that
// has a Score. A Finding whose Dossier cannot be built is logged and left
// out, so one odd Finding does not stop a Customer's Prioritization.
func openDossiers(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, bc business.Context) ([]assessment.Dossier, error) {
	found, err := tx.OpenFindingsOfCustomer(ctx, customer)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	cves := make([]string, 0, len(found))
	for _, f := range found {
		if !slices.Contains(cves, f.CVE) {
			cves = append(cves, f.CVE)
		}
	}
	threats, err := tx.ThreatsOf(ctx, cves)
	if err != nil {
		return nil, err
	}
	out := make([]assessment.Dossier, 0, len(found))
	for _, f := range found {
		d, err := dossierOf(f, threats[f.CVE], bc)
		if err != nil {
			log.Printf("agents: prioritizer: finding %s: %v", f.ID, err)
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

// dossierOfFinding reads one Finding of the Customer, open or closed, and
// builds its Dossier as it is now. It fails with ErrFindingNotFound when the
// Customer has no such Finding with a Score.
func dossierOfFinding(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, id uuid.UUID) (assessment.Dossier, error) {
	f, err := tx.FindingOfCustomer(ctx, customer, id)
	if errors.Is(err, postgres.ErrNotFound) {
		return assessment.Dossier{}, fmt.Errorf("%w: %w", ErrFindingNotFound, err)
	}
	if err != nil {
		return assessment.Dossier{}, err
	}
	threats, err := tx.ThreatsOf(ctx, []string{f.CVE})
	if err != nil {
		return assessment.Dossier{}, err
	}
	bc, err := tx.BusinessContext(ctx, customer)
	if err != nil {
		return assessment.Dossier{}, err
	}
	return dossierOf(f, threats[f.CVE], bc.Context)
}

func dossierOf(f postgres.CustomerFinding, threats postgres.Threats, bc business.Context) (assessment.Dossier, error) {
	var v stix2.Vulnerability
	if err := json.Unmarshal(f.Vulnerability, &v); err != nil {
		return assessment.Dossier{}, fmt.Errorf("vulnerability %s %w: %w", f.CVE, errUndecodable, err)
	}
	stored := assessment.Stored{
		Finding: f.ID.String(), Vulnerability: &v, Asset: f.Asset,
		ComponentName: f.ComponentName, ComponentVersion: f.ComponentVersion, Score: f.Score,
		Labeling: assessment.Labeling{Outcome: assessment.LabelingNotTried},
	}
	for _, a := range threats.Advisories {
		title, description, err := advisoryText(a)
		if err != nil {
			log.Printf("agents: %s: %v", f.CVE, err)
			continue
		}
		stored.Advisories = append(stored.Advisories, assessment.NewAdvisory(a.Feed, a.Published, title, description))
	}
	if l := threats.Labeling; l != nil {
		stored.Labeling = assessment.Labeling{Outcome: l.Outcome, Model: l.Model}
	}
	if stored.Labeling.Outcome == assessment.LabelingLabeled {
		stored.Techniques = techniquesOf(threats.Techniques)
	}
	for _, c := range bc.ServicesOf(f.Asset.Imported().Name()) {
		stored.CriticalServices = append(stored.CriticalServices, assessment.CriticalService{
			Name: c.Name, Description: c.Description, Impact: string(c.Impact), MaxDowntime: string(c.MaxDowntime),
		})
	}
	return assessment.NewDossier(stored)
}

// advisoryText is the title and description of a's STIX report.
func advisoryText(a postgres.StoredAdvisory) (title, description string, err error) {
	var report struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(a.Object, &report); err != nil {
		return "", "", fmt.Errorf("advisory %s %w: %w", a.ID, errUndecodable, err)
	}
	return report.Name, report.Description, nil
}

// techniquesOf is the Techniques of labels, each read as its current
// Technique, at most assessment.MaxTechniques, and each once when two labels
// were replaced by the same one.
func techniquesOf(labels []postgres.LabeledTechnique) []assessment.Technique {
	var out []assessment.Technique
	for _, l := range labels {
		t := assessment.Technique{
			AttackID: l.Label.AttackID, Tactics: []string{}, Role: l.Label.Role,
			Evidence: l.Label.Evidence, Rationale: l.Label.Rationale, Mitigations: []assessment.Mitigation{},
		}
		if c := l.Current; c != nil {
			t.AttackID, t.Name, t.Tactics = c.AttackID, c.Name, slices.Clone(c.Tactics)
			if c.AttackID != l.Label.AttackID {
				t.LabeledAs = l.Label.AttackID
			}
		}
		for _, m := range l.Mitigations {
			t.Mitigations = append(t.Mitigations, assessment.Mitigation{AttackID: m.AttackID, Name: m.Name, Advice: m.Advice})
		}
		if len(out) == assessment.MaxTechniques || slices.ContainsFunc(out, func(o assessment.Technique) bool { return o.AttackID == t.AttackID }) {
			continue
		}
		out = append(out, t)
	}
	return out
}
