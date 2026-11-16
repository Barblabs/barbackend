package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"barbackend/internal/postgres/sqlcgen"
)

// maxReplacements is how many revoked-by steps a read of a Technique follows:
// a revoked Technique can be replaced by one that was revoked later.
const maxReplacements = 5

// Threats is what barbattack stores about how a Vulnerability is attacked:
// the Advisories that name it (ADR 0022), and the Cartógrafo's Labeling of it
// with its Techniques (ADR 0024).
type Threats struct {
	// Advisories are newest first.
	Advisories []StoredAdvisory
	// Labeling is nil while the Cartógrafo has not tried to label it.
	Labeling *Labeling
	// Techniques are how it is exploited first, then what that gives and what
	// follows.
	Techniques []LabeledTechnique
}

// LabeledTechnique is a Technique label read through the stored catalog
// (ADR 0023): Current is the label's Technique, or the one that replaced it
// when it was revoked, and Mitigations are Current's. Current is nil when the
// catalog does not hold the label's ATT&CK id.
type LabeledTechnique struct {
	Label       TechniqueLabel
	Current     *AttackTechnique
	Mitigations []TechniqueMitigation
}

// ThreatsOf is the Threats of the stored Vulnerabilities of cves, by CVE ID,
// read in a number of queries that grows with the distinct Techniques, not
// with the Vulnerabilities.
func (t *Tx) ThreatsOf(ctx context.Context, cves []string) (map[string]Threats, error) {
	out := make(map[string]Threats, len(cves))
	advisories, err := t.q.ListAdvisoriesOfVulnerabilities(ctx, cves)
	if err != nil {
		return nil, fmt.Errorf("list advisories of %d vulnerabilities: %w", len(cves), err)
	}
	for _, row := range advisories {
		threats := out[row.CveID]
		threats.Advisories = append(threats.Advisories, StoredAdvisory{ID: row.ID, Feed: row.Feed, Published: row.PublishedAt, Object: row.Object, Modified: row.ModifiedAt})
		out[row.CveID] = threats
	}
	labelings, err := t.q.ListLabelingsOfVulnerabilities(ctx, cves)
	if err != nil {
		return nil, fmt.Errorf("list labelings of %d vulnerabilities: %w", len(cves), err)
	}
	for _, row := range labelings {
		threats := out[row.CveID]
		threats.Labeling = &Labeling{CVE: row.CveID, Outcome: row.Outcome, Attempts: int(row.Attempts), Model: row.Model, PromptHash: row.PromptHash, LabeledAt: row.LabeledAt}
		out[row.CveID] = threats
	}
	labels, err := t.q.ListTechniquesOfVulnerabilities(ctx, cves)
	if err != nil {
		return nil, fmt.Errorf("list techniques of %d vulnerabilities: %w", len(cves), err)
	}
	current, mitigations, err := t.currentTechniques(ctx, labels)
	if err != nil {
		return nil, err
	}
	for _, row := range labels {
		threats := out[row.CveID]
		labeled := LabeledTechnique{Label: TechniqueLabel{AttackID: row.AttackID, Role: row.Role, Evidence: row.Evidence, Rationale: row.Rationale}}
		if c, ok := current[row.AttackID]; ok {
			labeled.Current, labeled.Mitigations = &c, mitigations[c.ID]
		}
		threats.Techniques = append(threats.Techniques, labeled)
		out[row.CveID] = threats
	}
	return out, nil
}

// CVETechnique is a Technique label of a Vulnerability, read as the current
// Technique of the stored catalog (ADR 0023).
type CVETechnique struct {
	Role      string
	Technique CatalogTechnique
}

// TechniquesOfCVEs is the labels of the stored Vulnerabilities of cves, by
// CVE ID, each read as its current Technique, so a revoked one reads as what
// replaced it. A label whose ATT&CK id the catalog does not hold is left out,
// since its tactics are unknown. It reads one Technique per distinct ATT&CK
// id, not per label.
func (t *Tx) TechniquesOfCVEs(ctx context.Context, cves []string) (map[string][]CVETechnique, error) {
	labels, err := t.q.ListTechniquesOfVulnerabilities(ctx, cves)
	if err != nil {
		return nil, fmt.Errorf("list techniques of %d vulnerabilities: %w", len(cves), err)
	}
	current := map[string]*CatalogTechnique{}
	out := make(map[string][]CVETechnique, len(cves))
	for _, l := range labels {
		technique, read := current[l.AttackID]
		if !read {
			stored, err := t.currentTechnique(ctx, l.AttackID)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			if err == nil {
				technique = &CatalogTechnique{AttackID: stored.AttackID, Name: stored.Name, Tactics: stored.Tactics}
			}
			current[l.AttackID] = technique
		}
		if technique != nil {
			out[l.CveID] = append(out[l.CveID], CVETechnique{Role: l.Role, Technique: *technique})
		}
	}
	return out, nil
}

// currentTechniques reads the current Technique of each distinct ATT&CK id
// the labels name, and the Mitigations of those Techniques by STIX id.
func (t *Tx) currentTechniques(ctx context.Context, labels []sqlcgen.VulnerabilityTechnique) (map[string]AttackTechnique, map[string][]TechniqueMitigation, error) {
	current := map[string]AttackTechnique{}
	var ids []string
	for _, l := range labels {
		if _, ok := current[l.AttackID]; ok {
			continue
		}
		technique, err := t.currentTechnique(ctx, l.AttackID)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		current[l.AttackID] = technique
		if !slices.Contains(ids, technique.ID) {
			ids = append(ids, technique.ID)
		}
	}
	mitigations := map[string][]TechniqueMitigation{}
	if len(ids) == 0 {
		return current, mitigations, nil
	}
	rows, err := t.q.ListMitigationsOfTechniques(ctx, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("list mitigations of %d techniques: %w", len(ids), err)
	}
	for _, row := range rows {
		mitigations[row.TechniqueID] = append(mitigations[row.TechniqueID], TechniqueMitigation{AttackID: row.AttackID, Name: row.Name, Advice: row.Description})
	}
	return current, mitigations, nil
}

// currentTechnique follows revoked-by so a label of a revoked Technique reads
// as what replaced it (ADR 0023).
func (t *Tx) currentTechnique(ctx context.Context, attackID string) (AttackTechnique, error) {
	technique, err := t.AttackTechnique(ctx, attackID)
	if err != nil {
		return AttackTechnique{}, err
	}
	for step := 0; technique.Revoked && step < maxReplacements; step++ {
		next, err := t.RevokingTechnique(ctx, technique.ID)
		if errors.Is(err, ErrNotFound) {
			break
		}
		if err != nil {
			return AttackTechnique{}, err
		}
		technique = next
	}
	return technique, nil
}
