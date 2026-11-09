package postgres_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/matching"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/scoring"
	"barbackend/internal/stixext"
)

var (
	nginx = inventory.SoftwareComponent{Role: inventory.Application, Name: "Nginx of payments", Version: "1.18.0", Product: inventory.Product{Vendor: "F5", Name: "Nginx"}}
	vault = inventory.SoftwareComponent{Role: inventory.Application, Name: "Vault of payments", Version: "1.16.1", Product: inventory.Product{Vendor: "hashicorp", Name: "vault"}}
	bash  = inventory.SoftwareComponent{Role: inventory.Application, Name: "bash", Version: "5.1"}
)

// findingWorld is one Customer's CMDB Source with a payments server (High,
// nginx and Vault) and a lab server (Low, nginx), and CVE-2021-23017 stored.
type findingWorld struct {
	db       *postgres.DB
	source   inventory.CMDBSourceID
	payments inventory.SourceReference
	lab      inventory.SourceReference
}

func newFindingWorld(t *testing.T) findingWorld {
	t.Helper()
	db := pgtest.NewDB(t)
	src := newSource(t, db, newCustomer(t, db))
	w := findingWorld{
		db:       db,
		source:   src.ID(),
		payments: inventory.SourceReference{Source: src.ID(), RecordID: "1"},
		lab:      inventory.SourceReference{Source: src.ID(), RecordID: "2"},
	}
	syncRecords(t, db, src.ID(), w.paymentsRecord(t), w.labRecord(t))
	storeVulnerability(t, db, "CVE-2021-23017", time.Now(), vulnerabilityObject("CVE-2021-23017", "Analyzed", `[]`))
	return w
}

func (w findingWorld) paymentsRecord(t *testing.T) inventory.Record {
	return inventory.Record{RecordID: "1", Imported: mustImported(t, inventory.ImportedAssetParams{
		Name: "payments", Kind: inventory.Server, Criticality: inventory.CriticalityHigh, Software: []inventory.SoftwareComponent{nginx, vault, bash},
	})}
}

func (w findingWorld) labRecord(t *testing.T) inventory.Record {
	return inventory.Record{RecordID: "2", Imported: mustImported(t, inventory.ImportedAssetParams{
		Name: "lab", Kind: inventory.Server, Criticality: inventory.CriticalityLow, Software: []inventory.SoftwareComponent{nginx},
	})}
}

// match builds the Match of CVE-2021-23017 on nginx of asset at version.
func match(t *testing.T, asset inventory.SourceReference, version string, flags ...matching.Flag) finding.Match {
	t.Helper()
	c := nginx
	c.Version = version
	m, err := finding.NewMatch(asset, c, "CVE-2021-23017", matching.Result{
		Matched: true, Evidence: stixext.Affected{Vendor: "f5", Product: "nginx", Version: "*", VersionEndExcluding: "1.20.1"}, Flags: flags,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func saveMatch(t *testing.T, db *postgres.DB, m finding.Match) (finding.ID, finding.Outcome) {
	t.Helper()
	var id finding.ID
	var outcome finding.Outcome
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		id, outcome, err = tx.SaveMatch(context.Background(), m)
		return err
	})
	return id, outcome
}

func openFindingsOf(t *testing.T, db *postgres.DB, cve string) []postgres.OpenFinding {
	t.Helper()
	var open []postgres.OpenFinding
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		open, err = tx.OpenFindingsOfVulnerability(context.Background(), cve)
		return err
	})
	return open
}

func TestComponentsWithProductsReadsActiveAssetsIgnoringCase(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	var got []postgres.Candidate
	inTx(t, w.db, func(tx *postgres.Tx) (err error) {
		got, err = tx.ComponentsWithProducts(context.Background(), []inventory.Product{{Vendor: "f5", Name: "nginx"}})
		return err
	})
	if len(got) != 2 || got[0].Asset != w.payments || got[1].Asset != w.lab {
		t.Fatalf("candidates = %+v, want nginx of payments and of lab", got)
	}
	if got[0].Component != nginx || got[0].Criticality != inventory.CriticalityHigh || got[0].Position != 0 {
		t.Errorf("payments candidate = %+v", got[0])
	}

	syncRecords(t, w.db, w.source, w.paymentsRecord(t))
	inTx(t, w.db, func(tx *postgres.Tx) (err error) {
		got, err = tx.ComponentsWithProducts(context.Background(), []inventory.Product{{Vendor: "f5", Name: "nginx"}})
		return err
	})
	if len(got) != 1 || got[0].Asset != w.payments {
		t.Errorf("candidates after lab became Inactive = %+v, want only payments", got)
	}
}

func TestComponentsOfSourceReadsEveryComponentOfItsActiveAssets(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	syncRecords(t, w.db, w.source, w.paymentsRecord(t))
	var got []postgres.Candidate
	inTx(t, w.db, func(tx *postgres.Tx) (err error) {
		got, err = tx.ComponentsOfSource(context.Background(), w.source)
		return err
	})
	var names []string
	for _, c := range got {
		names = append(names, c.Component.Name)
	}
	if !slices.Equal(names, []string{nginx.Name, vault.Name, bash.Name}) {
		t.Errorf("components = %v, want payments' three in order and none of the Inactive lab", names)
	}
}

func TestSaveMatchOpensUpdatesAndReopensTheSameFinding(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	ctx := context.Background()

	id, outcome := saveMatch(t, w.db, match(t, w.payments, "1.18.0", matching.VersionUnparsed))
	if outcome != finding.Opened {
		t.Fatalf("first match = %v, want opened", outcome)
	}
	again, outcome := saveMatch(t, w.db, match(t, w.payments, "1.19.0"))
	if outcome != finding.Updated || again != id {
		t.Fatalf("second match = %v %v, want updated %v", outcome, again, id)
	}
	open := openFindingsOf(t, w.db, "CVE-2021-23017")
	if len(open) != 1 || open[0].ComponentVersion != "1.19.0" || open[0].Key.Vendor != "f5" || open[0].Criticality != inventory.CriticalityHigh {
		t.Fatalf("open findings = %+v, want payments at 1.19.0", open)
	}
	inTx(t, w.db, func(tx *postgres.Tx) error {
		flags, err := tx.MatchFlags(ctx, id)
		if len(flags) != 0 {
			t.Errorf("flags = %v, want them replaced by none", flags)
		}
		return err
	})

	inTx(t, w.db, func(tx *postgres.Tx) error {
		_, err := tx.CloseFinding(ctx, id, finding.NoLongerAffected)
		return err
	})
	if open := openFindingsOf(t, w.db, "CVE-2021-23017"); len(open) != 0 {
		t.Fatalf("open findings after closing = %+v", open)
	}
	reopened, outcome := saveMatch(t, w.db, match(t, w.payments, "1.18.0", matching.DistroBackport))
	if outcome != finding.Reopened || reopened != id {
		t.Fatalf("match after closing = %v %v, want reopened %v", outcome, reopened, id)
	}
	inTx(t, w.db, func(tx *postgres.Tx) error {
		flags, err := tx.MatchFlags(ctx, id)
		if !slices.Equal(flags, []matching.Flag{matching.DistroBackport}) {
			t.Errorf("flags = %v, want distro_backport", flags)
		}
		return err
	})
}

func TestCloseFindingClosesOnlyAnOpenFinding(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	id, _ := saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	for i, want := range []bool{true, false} {
		inTx(t, w.db, func(tx *postgres.Tx) error {
			closed, err := tx.CloseFinding(context.Background(), id, finding.ComponentRemoved)
			if closed != want {
				t.Errorf("close %d = %t, want %t", i+1, closed, want)
			}
			return err
		})
	}
}

func TestCloseFindingsOfInactiveAssetsClosesOnlyThose(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	saveMatch(t, w.db, match(t, w.lab, "1.18.0"))
	syncRecords(t, w.db, w.source, w.paymentsRecord(t))

	inTx(t, w.db, func(tx *postgres.Tx) error {
		n, err := tx.CloseFindingsOfInactiveAssets(context.Background(), w.source)
		if n != 1 {
			t.Errorf("closed = %d, want the lab's one", n)
		}
		return err
	})
	if open := openFindingsOf(t, w.db, "CVE-2021-23017"); len(open) != 1 || open[0].Key.Asset != w.payments {
		t.Errorf("open findings = %+v, want only payments", open)
	}
}

func TestOpenFindingsOfSourceReadsOnlyItsOpenFindings(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	lab, _ := saveMatch(t, w.db, match(t, w.lab, "1.18.0"))
	inTx(t, w.db, func(tx *postgres.Tx) error {
		_, err := tx.CloseFinding(context.Background(), lab, finding.NoLongerAffected)
		return err
	})

	var got []postgres.OpenFinding
	inTx(t, w.db, func(tx *postgres.Tx) (err error) {
		got, err = tx.OpenFindingsOfSource(context.Background(), w.source)
		return err
	})
	if len(got) != 1 || got[0].Key.Asset != w.payments || got[0].Key.CVE != "CVE-2021-23017" {
		t.Errorf("open findings = %+v, want payments' only", got)
	}
}

func TestSaveScoreIfChangedStoresOnlyAChangedScore(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	id, _ := saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	score := scoring.Score{
		Model: 1, Value: 0.308,
		Factors: scoring.Factors{Alpha: 0.81, Beta: 0.9, Gamma: 0, Vulnerability: 0.513, CriticalityMultiplier: 1, ExposureMultiplier: 0.6},
	}
	withGap := score
	withGap.Gaps = []scoring.DataGap{scoring.ExposureUndeclared}

	for i, step := range []struct {
		score  scoring.Score
		stored bool
	}{
		{score, true},
		{score, false},
		{withGap, true},
		{withGap, false},
	} {
		inTx(t, w.db, func(tx *postgres.Tx) error {
			stored, err := tx.SaveScoreIfChanged(context.Background(), id, step.score)
			if stored != step.stored {
				t.Errorf("save %d stored = %t, want %t", i+1, stored, step.stored)
			}
			return err
		})
	}
	inTx(t, w.db, func(tx *postgres.Tx) error {
		latest, err := tx.LatestScore(context.Background(), id)
		if latest.Value != 0.308 || !slices.Equal(latest.Gaps, withGap.Gaps) || latest.Factors != withGap.Factors {
			t.Errorf("latest score = %+v, want %+v", latest, withGap)
		}
		return err
	})
}
