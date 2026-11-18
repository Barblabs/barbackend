package findings_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"barbackend/internal/findings"
	"barbackend/internal/inventory"
	"barbackend/internal/scoring"
	"github.com/google/uuid"
)

func TestRescoreAssetScoresItsOpenFindingsWithTheDeclaredClassification(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	w.findings = findings.New(w.db, scoring.Model3, time.Hour)
	payments := inventory.SourceReference{Source: w.source, RecordID: "payments"}
	rescore := func() (model int16, multiplier *float64, gaps []string) {
		t.Helper()
		if err := w.findings.RescoreAsset(context.Background(), payments); err != nil {
			t.Fatal(err)
		}
		_, _, gaps, _ = w.latestScore(t, f.id)
		if err := w.conn.QueryRow(context.Background(), `
			SELECT model, information_classification_multiplier
			FROM finding_scores WHERE finding_id = $1 ORDER BY scored_at DESC LIMIT 1`, f.id).Scan(&model, &multiplier); err != nil {
			t.Fatal(err)
		}
		return model, multiplier, gaps
	}
	const undeclared = "information_classification_undeclared"

	if model, m, gaps := rescore(); model != 3 || m != nil || !slices.Contains(gaps, undeclared) {
		t.Errorf("unclassified: model %d, multiplier %v, gaps %v; want Model 3, none and %s", model, m, gaps, undeclared)
	}

	declareClassification(t, w, "payments", inventory.ClassifiedPublic)
	if _, m, gaps := rescore(); m == nil || *m != 0.5 || slices.Contains(gaps, undeclared) {
		t.Errorf("declared Public: multiplier %v, gaps %v; want 0.5 without %s", m, gaps, undeclared)
	}

	declareClassification(t, w, "payments", inventory.Unclassified)
	if _, m, gaps := rescore(); m != nil || !slices.Contains(gaps, undeclared) {
		t.Errorf("cleared: multiplier %v, gaps %v; want none with %s", m, gaps, undeclared)
	}
}

// declareClassification stores a Customer Admin's Declaration of the
// record's Information Classification, or clears it for Unclassified, as the
// assets use case does, without rescoring.
func declareClassification(t *testing.T, w world, record string, c inventory.InformationClassification) {
	t.Helper()
	if c == inventory.Unclassified {
		w.exec(t, `UPDATE assets SET declared_information_classification_id = NULL, information_classification_declared_by = NULL,
			information_classification_declared_at = NULL WHERE record_id = $1`, record)
		return
	}
	w.exec(t, `
		WITH admin AS (
			INSERT INTO users (id, cognito_sub, email, customer_id, role_id)
			SELECT gen_random_uuid(), gen_random_uuid()::text, 'admin@example.com', customer_id, 2
			FROM cmdb_sources WHERE id = $3
			ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
			RETURNING id
		)
		UPDATE assets
		SET declared_information_classification_id = $1, information_classification_declared_by = (SELECT id FROM admin),
		    information_classification_declared_at = now()
		WHERE record_id = $2`, int16(c), record, uuid.UUID(w.source))
}

func TestRescoreAssetScoresItsOpenFindingsWithTheDeclaredExposure(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	payments := inventory.SourceReference{Source: w.source, RecordID: "payments"}
	rescore := func() (multiplier float64, gaps []string, scores int) {
		t.Helper()
		if err := w.findings.RescoreAsset(context.Background(), payments); err != nil {
			t.Fatal(err)
		}
		_, _, gaps, scores = w.latestScore(t, f.id)
		return w.latestMultipliers(t, f.id).exposure, gaps, scores
	}

	w.declareExposure(t, "payments", inventory.Internal)
	if m, gaps, scores := rescore(); m != 0.6 || slices.Contains(gaps, "exposure_undeclared") || scores != 2 {
		t.Errorf("declared Internal: multiplier %v, gaps %v, %d scores; want 0.6 without exposure_undeclared in a second score", m, gaps, scores)
	}
	if _, _, scores := rescore(); scores != 2 {
		t.Errorf("rescored unchanged: %d scores, want still 2", scores)
	}

	w.declareExposure(t, "payments", inventory.ExposureUnknown)
	if m, gaps, scores := rescore(); m != 1 || !slices.Contains(gaps, "exposure_undeclared") || scores != 3 {
		t.Errorf("cleared: multiplier %v, gaps %v, %d scores; want 1 with exposure_undeclared in a third score", m, gaps, scores)
	}
}
