package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/postgres/sqlcgen"
	"github.com/jackc/pgx/v5"
)

// The outcomes of a Labeling (ADR 0024). Labeled and none are final; failed
// is tried again while attempts last.
const (
	LabelingLabeled = "labeled"
	LabelingNone    = "none"
	LabelingFailed  = "failed"
)

// Labeling is the Cartógrafo's last attempt to label a Vulnerability.
type Labeling struct {
	CVE        string
	Outcome    string
	Attempts   int
	Model      string
	PromptHash string
	LabeledAt  time.Time
}

// TechniqueLabel is an ATT&CK Technique a Vulnerability is labeled with, by
// its ATT&CK id as the Cartógrafo gave it, with its role and the quote that
// supports it.
type TechniqueLabel struct {
	AttackID  string
	Role      string
	Evidence  string
	Rationale string
}

// UnlabeledVulnerabilities is the CVE IDs of at most limit stored
// Vulnerabilities with no Labeling, or with a failed one of fewer than
// maxAttempts attempts, newest first.
func (t *Tx) UnlabeledVulnerabilities(ctx context.Context, limit, maxAttempts int) ([]string, error) {
	cves, err := t.q.ListUnlabeledVulnerabilities(ctx, sqlcgen.ListUnlabeledVulnerabilitiesParams{
		MaxAttempts: int32(maxAttempts), MaxVulnerabilities: int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("list unlabeled vulnerabilities: %w", err)
	}
	return cves, nil
}

// StoreLabeling stores the final Labeling of the Vulnerability of cve with
// its labels, labeled when there are any and none otherwise. It fails with
// ErrLabeled when the Vulnerability already has a final Labeling.
func (t *Tx) StoreLabeling(ctx context.Context, cve, model, promptHash string, labels []TechniqueLabel) error {
	outcome := LabelingNone
	if len(labels) > 0 {
		outcome = LabelingLabeled
	}
	if err := t.recordLabeling(ctx, cve, outcome, model, promptHash); err != nil {
		return err
	}
	for _, l := range labels {
		if err := t.q.InsertVulnerabilityTechnique(ctx, sqlcgen.InsertVulnerabilityTechniqueParams{
			CveID: cve, AttackID: l.AttackID, Role: l.Role, Evidence: l.Evidence, Rationale: l.Rationale,
		}); err != nil {
			return fmt.Errorf("label %s with %s: %w", cve, l.AttackID, err)
		}
	}
	return nil
}

// StoreFailedLabeling counts one more failed attempt to label the
// Vulnerability of cve. It fails with ErrLabeled when the Vulnerability
// already has a final Labeling.
func (t *Tx) StoreFailedLabeling(ctx context.Context, cve, model, promptHash string) error {
	return t.recordLabeling(ctx, cve, LabelingFailed, model, promptHash)
}

func (t *Tx) recordLabeling(ctx context.Context, cve, outcome, model, promptHash string) error {
	n, err := t.q.RecordLabeling(ctx, sqlcgen.RecordLabelingParams{CveID: cve, Outcome: outcome, Model: model, PromptHash: promptHash})
	if err != nil {
		return fmt.Errorf("record %s labeling of %s: %w", outcome, cve, err)
	}
	if n == 0 {
		return fmt.Errorf("record %s labeling of %s: %w", outcome, cve, ErrLabeled)
	}
	return nil
}

// LabelingOf is the Labeling of the Vulnerability of cve. It fails with
// ErrNotFound when the Cartógrafo has not tried to label it yet.
func (t *Tx) LabelingOf(ctx context.Context, cve string) (Labeling, error) {
	row, err := t.q.GetVulnerabilityLabeling(ctx, cve)
	if errors.Is(err, pgx.ErrNoRows) {
		return Labeling{}, fmt.Errorf("labeling of %s: %w", cve, ErrNotFound)
	}
	if err != nil {
		return Labeling{}, fmt.Errorf("get labeling of %s: %w", cve, err)
	}
	return Labeling{
		CVE: row.CveID, Outcome: row.Outcome, Attempts: int(row.Attempts),
		Model: row.Model, PromptHash: row.PromptHash, LabeledAt: row.LabeledAt,
	}, nil
}

// TechniquesOf is the labels of the Vulnerability of cve: how it is exploited
// first, then what that gives and what follows.
func (t *Tx) TechniquesOf(ctx context.Context, cve string) ([]TechniqueLabel, error) {
	rows, err := t.q.ListTechniquesOfVulnerability(ctx, cve)
	if err != nil {
		return nil, fmt.Errorf("list techniques of %s: %w", cve, err)
	}
	out := make([]TechniqueLabel, len(rows))
	for i, row := range rows {
		out[i] = TechniqueLabel{AttackID: row.AttackID, Role: row.Role, Evidence: row.Evidence, Rationale: row.Rationale}
	}
	return out, nil
}
