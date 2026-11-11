package postgres_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
)

const (
	cartografo = "claude-haiku-5-5"
	promptHash = "sha256:0f1e2d"
)

func storedCVEs(t *testing.T, cves ...string) *postgres.DB {
	t.Helper()
	db := pgtest.NewDB(t)
	for _, cve := range cves {
		storeVulnerability(t, db, cve, may, vulnerabilityObject(cve, "Analyzed", `[]`))
	}
	return db
}

func unlabeled(t *testing.T, db *postgres.DB, limit, maxAttempts int) []string {
	t.Helper()
	return inTxValue(t, db, func(tx *postgres.Tx) ([]string, error) {
		return tx.UnlabeledVulnerabilities(context.Background(), limit, maxAttempts)
	})
}

func labelingOf(t *testing.T, db *postgres.DB, cve string) postgres.Labeling {
	t.Helper()
	return inTxValue(t, db, func(tx *postgres.Tx) (postgres.Labeling, error) { return tx.LabelingOf(context.Background(), cve) })
}

func storeLabeling(db *postgres.DB, cve string, labels ...postgres.TechniqueLabel) error {
	return db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.StoreLabeling(context.Background(), cve, cartografo, promptHash, labels)
	})
}

func storeFailedLabeling(db *postgres.DB, cve string) error {
	return db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.StoreFailedLabeling(context.Background(), cve, cartografo, promptHash)
	})
}

func TestStoreLabelingKeepsItsTechniquesInTheOrderOfAnAttack(t *testing.T) {
	t.Parallel()
	db := storedCVEs(t, "CVE-2026-0001")
	if err := storeLabeling(db, "CVE-2026-0001",
		postgres.TechniqueLabel{AttackID: "T1059", Role: "primary_impact", Evidence: "execute arbitrary commands", Rationale: "It runs commands."},
		postgres.TechniqueLabel{AttackID: "T1190", Role: "exploitation", Evidence: "a crafted HTTP request", Rationale: "It is reached over HTTP."},
	); err != nil {
		t.Fatal(err)
	}

	got := inTxValue(t, db, func(tx *postgres.Tx) ([]postgres.TechniqueLabel, error) {
		return tx.TechniquesOf(context.Background(), "CVE-2026-0001")
	})
	if len(got) != 2 || got[0].AttackID != "T1190" || got[1].AttackID != "T1059" {
		t.Errorf("techniques = %+v, want T1190 (exploitation) before T1059 (primary_impact)", got)
	}
	if l := labelingOf(t, db, "CVE-2026-0001"); l.Outcome != postgres.LabelingLabeled || l.Attempts != 1 || l.Model != cartografo || l.PromptHash != promptHash {
		t.Errorf("labeling = %+v, want labeled on the first attempt, with its model and prompt hash", l)
	}
}

func TestALabelingWithNoTechniquesIsNone(t *testing.T) {
	t.Parallel()
	db := storedCVEs(t, "CVE-2026-0001")
	if err := storeLabeling(db, "CVE-2026-0001"); err != nil {
		t.Fatal(err)
	}

	if l := labelingOf(t, db, "CVE-2026-0001"); l.Outcome != postgres.LabelingNone {
		t.Errorf("outcome = %s, want none", l.Outcome)
	}
}

func TestAFinalLabelingIsNotRecordedAgain(t *testing.T) {
	t.Parallel()
	db := storedCVEs(t, "CVE-2026-0001")
	if err := storeLabeling(db, "CVE-2026-0001"); err != nil {
		t.Fatal(err)
	}

	if err := storeLabeling(db, "CVE-2026-0001"); !errors.Is(err, postgres.ErrLabeled) {
		t.Errorf("second labeling err = %v, want ErrLabeled", err)
	}
	if err := storeFailedLabeling(db, "CVE-2026-0001"); !errors.Is(err, postgres.ErrLabeled) {
		t.Errorf("failed attempt after a final labeling err = %v, want ErrLabeled", err)
	}
}

func TestAFailedLabelingCountsItsAttemptsUntilOneSucceeds(t *testing.T) {
	t.Parallel()
	db := storedCVEs(t, "CVE-2026-0001")
	for range 2 {
		if err := storeFailedLabeling(db, "CVE-2026-0001"); err != nil {
			t.Fatal(err)
		}
	}
	if l := labelingOf(t, db, "CVE-2026-0001"); l.Outcome != postgres.LabelingFailed || l.Attempts != 2 {
		t.Errorf("labeling = %+v, want failed after 2 attempts", l)
	}

	if err := storeLabeling(db, "CVE-2026-0001", postgres.TechniqueLabel{AttackID: "T1190", Role: "exploitation", Evidence: "remote", Rationale: "Remote."}); err != nil {
		t.Fatal(err)
	}
	if l := labelingOf(t, db, "CVE-2026-0001"); l.Outcome != postgres.LabelingLabeled || l.Attempts != 3 {
		t.Errorf("labeling = %+v, want labeled on the third attempt", l)
	}
}

func TestUnlabeledVulnerabilitiesAreThoseWithAttemptsLeft(t *testing.T) {
	t.Parallel()
	db := storedCVEs(t, "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004")
	if err := storeLabeling(db, "CVE-2026-0001"); err != nil {
		t.Fatal(err)
	}
	if err := storeFailedLabeling(db, "CVE-2026-0002"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := storeFailedLabeling(db, "CVE-2026-0003"); err != nil {
			t.Fatal(err)
		}
	}

	got := unlabeled(t, db, 50, 3)
	slices.Sort(got)
	if want := []string{"CVE-2026-0002", "CVE-2026-0004"}; !slices.Equal(got, want) {
		t.Errorf("unlabeled = %v, want %v: not the final one nor the one out of attempts", got, want)
	}
}

func TestUnlabeledVulnerabilitiesAreTheNewestFirstUpToTheLimit(t *testing.T) {
	t.Parallel()
	db := storedCVEs(t, "CVE-2026-0001")
	time.Sleep(10 * time.Millisecond) // stored_at is the database's now()
	storeVulnerability(t, db, "CVE-2026-0002", may, vulnerabilityObject("CVE-2026-0002", "Analyzed", `[]`))

	if got := unlabeled(t, db, 1, 3); !slices.Equal(got, []string{"CVE-2026-0002"}) {
		t.Errorf("unlabeled = %v, want only the newest one", got)
	}
}

func TestLabelingsSinceCountsTheAttemptsAfterAMoment(t *testing.T) {
	t.Parallel()
	db := storedCVEs(t, "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003")
	before := time.Now().Add(-time.Minute)
	if err := storeLabeling(db, "CVE-2026-0001"); err != nil {
		t.Fatal(err)
	}
	if err := storeFailedLabeling(db, "CVE-2026-0002"); err != nil {
		t.Fatal(err)
	}

	count := func(since time.Time) int {
		return inTxValue(t, db, func(tx *postgres.Tx) (int, error) { return tx.LabelingsSince(context.Background(), since) })
	}
	if got := count(before); got != 2 {
		t.Errorf("labelings since a minute ago = %d, want 2", got)
	}
	if got := count(time.Now().Add(time.Minute)); got != 0 {
		t.Errorf("labelings since a minute from now = %d, want 0", got)
	}
}

func TestLabelingOfAVulnerabilityNotTriedIsNotFound(t *testing.T) {
	t.Parallel()
	db := storedCVEs(t, "CVE-2026-0001")

	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.LabelingOf(context.Background(), "CVE-2026-0001")
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
