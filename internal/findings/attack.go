package findings

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"barbackend/internal/postgres"
	"barbackend/internal/stixext"
	"barbackend/internal/tenancy"
)

// The roles of a Technique label (ADR 0024).
const (
	RoleExploitation    = "exploitation"
	RolePrimaryImpact   = "primary_impact"
	RoleSecondaryImpact = "secondary_impact"
)

// tacticOrder is the order of the ATT&CK Enterprise tactics along an attack.
// A tactic of the catalog not listed here goes after them, by name.
var tacticOrder = []string{
	"reconnaissance", "resource-development", "initial-access", "execution", "persistence",
	"privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
	"collection", "command-and-control", "exfiltration", "impact",
}

// TacticCount is the open Findings with a Technique of one tactic.
type TacticCount struct {
	Tactic string
	Bands  BandCounts
}

// TechniqueCount is the open Findings with one Technique.
type TechniqueCount struct {
	AttackID string
	Name     string
	Tactics  []string
	// Roles are the roles it is labeled with on those Findings' CVEs.
	Roles []string
	Bands BandCounts
}

// AttackMatrix is the Customer's open scored Findings by the ATT&CK tactics
// and Techniques the Cartógrafo labeled their CVEs with (ADR 0024).
type AttackMatrix struct {
	// Open counts every open scored Finding, and Labeled those whose CVE
	// has a label, whatever its role.
	Open, Labeled int
	// Tactics are every tactic of the catalog, in attack order.
	Tactics []TacticCount
	// Techniques are the ones with the most Findings, most first.
	Techniques []TechniqueCount
}

// AttackMatrix counts the Customer's open scored Findings by Score Band
// within each ATT&CK tactic and Technique their CVE is labeled with, only by
// the labels of role when it is not empty. A Finding counts once in each
// tactic and each Technique it has, so the tactics do not add up to the
// Findings. Techniques holds at most limit; a zero limit takes
// DefaultTopLimit. It fails with ErrInvalidCount.
func (s *Service) AttackMatrix(ctx context.Context, caller tenancy.User, role string, limit int) (AttackMatrix, error) {
	if role != "" && role != RoleExploitation && role != RolePrimaryImpact && role != RoleSecondaryImpact {
		return AttackMatrix{}, fmt.Errorf("%w: role %q", ErrInvalidCount, role)
	}
	limit, err := topLimit(limit)
	if err != nil {
		return AttackMatrix{}, err
	}
	customer, err := caller.ActsFor()
	if err != nil {
		return AttackMatrix{}, err
	}
	var facts []postgres.OpenFindingFact
	var byCVE map[string][]postgres.CVETechnique
	var catalog []postgres.CatalogTechnique
	err = s.db.InTx(ctx, func(tx *postgres.Tx) (err error) {
		if facts, err = tx.OpenFindingFactsOfCustomer(ctx, customer, string(stixext.KEVDefinitionID), string(stixext.EPSSDefinitionID)); err != nil {
			return err
		}
		if byCVE, err = tx.TechniquesOfCVEs(ctx, distinctCVEs(facts)); err != nil {
			return err
		}
		catalog, err = tx.CurrentTechniques(ctx)
		return err
	})
	if err != nil {
		return AttackMatrix{}, err
	}
	tally := matrixTally{matrix: AttackMatrix{Open: len(facts), Tactics: orderedTactics(catalog, byCVE)}, techniques: map[string]*TechniqueCount{}}
	for _, f := range facts {
		tally.count(f, byCVE[f.CVE], role)
	}
	return tally.done(limit), nil
}

type matrixTally struct {
	matrix     AttackMatrix
	techniques map[string]*TechniqueCount
}

// count adds f, whose CVE has labels, by those of role, or by all of them
// when role is empty.
func (t *matrixTally) count(f postgres.OpenFindingFact, labels []postgres.CVETechnique, role string) {
	if len(labels) > 0 {
		t.matrix.Labeled++
	}
	labels = slices.DeleteFunc(slices.Clone(labels), func(l postgres.CVETechnique) bool { return role != "" && l.Role != role })
	var tactics []string
	for _, l := range labels {
		tactics = appendNew(tactics, l.Technique.Tactics...)
	}
	for i := range t.matrix.Tactics {
		if slices.Contains(tactics, t.matrix.Tactics[i].Tactic) {
			t.matrix.Tactics[i].Bands.Add(f.Score)
		}
	}
	var counted []string
	for _, l := range labels {
		technique := t.technique(l)
		technique.Roles = appendNew(technique.Roles, l.Role)
		if !slices.Contains(counted, technique.AttackID) {
			counted = append(counted, technique.AttackID)
			technique.Bands.Add(f.Score)
		}
	}
}

func (t *matrixTally) technique(l postgres.CVETechnique) *TechniqueCount {
	technique := t.techniques[l.Technique.AttackID]
	if technique == nil {
		technique = &TechniqueCount{AttackID: l.Technique.AttackID, Name: l.Technique.Name, Tactics: l.Technique.Tactics}
		t.techniques[l.Technique.AttackID] = technique
	}
	return technique
}

// done is the matrix with at most limit Techniques, those with the most
// Findings first.
func (t *matrixTally) done(limit int) AttackMatrix {
	for _, technique := range t.techniques {
		slices.Sort(technique.Roles)
		t.matrix.Techniques = append(t.matrix.Techniques, *technique)
	}
	slices.SortFunc(t.matrix.Techniques, func(a, b TechniqueCount) int {
		return cmp.Or(cmp.Compare(b.Bands.Total(), a.Bands.Total()), moreSevere(a.Bands, b.Bands), strings.Compare(a.AttackID, b.AttackID))
	})
	t.matrix.Techniques = t.matrix.Techniques[:min(limit, len(t.matrix.Techniques))]
	return t.matrix
}

func appendNew(values []string, more ...string) []string {
	for _, v := range more {
		if !slices.Contains(values, v) {
			values = append(values, v)
		}
	}
	return values
}

func distinctCVEs(facts []postgres.OpenFindingFact) []string {
	var cves []string
	for _, f := range facts {
		cves = appendNew(cves, f.CVE)
	}
	return cves
}

// orderedTactics is a zero count of every tactic of the catalog and of the
// labels, in attack order.
func orderedTactics(catalog []postgres.CatalogTechnique, byCVE map[string][]postgres.CVETechnique) []TacticCount {
	var tactics []string
	for _, t := range catalog {
		tactics = appendNew(tactics, t.Tactics...)
	}
	for _, labels := range byCVE {
		for _, l := range labels {
			tactics = appendNew(tactics, l.Technique.Tactics...)
		}
	}
	rank := func(t string) int {
		if i := slices.Index(tacticOrder, t); i >= 0 {
			return i
		}
		return len(tacticOrder)
	}
	slices.SortFunc(tactics, func(a, b string) int { return cmp.Or(cmp.Compare(rank(a), rank(b)), strings.Compare(a, b)) })
	counts := make([]TacticCount, len(tactics))
	for i, t := range tactics {
		counts[i] = TacticCount{Tactic: t}
	}
	return counts
}
