package postgres_test

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/matching"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"barbackend/internal/tenancy"
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
	customer tenancy.CustomerID
	source   inventory.CMDBSourceID
	payments inventory.SourceReference
	lab      inventory.SourceReference
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
	if got[0].Component != nginx || got[0].Values.Criticality != inventory.CriticalityHigh || got[0].Position != 0 {
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
	if len(open) != 1 || open[0].ComponentVersion != "1.19.0" || open[0].Key.Vendor != "f5" || open[0].Values.Criticality != inventory.CriticalityHigh {
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

func TestScoringReadsTheDeclaredInformationClassification(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	saveMatch(t, w.db, match(t, w.lab, "1.18.0"))
	admin := storeUser(t, w.db, "admin@example.com", tenancy.CustomerAdmin, w.customer)
	page := inTxValue(t, w.db, func(tx *postgres.Tx) (postgres.AssetPage, error) {
		return tx.ListAssets(context.Background(), postgres.AssetListQuery{Customer: w.customer, Limit: 10})
	})
	for _, a := range page.Assets {
		if a.Asset.Ref() == w.payments {
			declareConfidential(t, w.db, w.customer, a.ID, admin.ID())
		}
	}
	want := map[inventory.SourceReference]inventory.InformationClassification{
		w.payments: inventory.ClassifiedConfidential,
		w.lab:      inventory.Unclassified,
	}

	candidates := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.Candidate, error) {
		return tx.ComponentsWithProducts(context.Background(), []inventory.Product{{Vendor: "f5", Name: "nginx"}})
	})
	for _, c := range candidates {
		if c.Values.Classification != want[c.Asset] {
			t.Errorf("candidate on %v classification = %v, want %v", c.Asset, c.Values.Classification, want[c.Asset])
		}
	}
	open := openFindingsOf(t, w.db, "CVE-2021-23017")
	if len(open) != 2 {
		t.Fatalf("open findings = %+v, want payments' and lab's", open)
	}
	for _, f := range open {
		if f.Values.Classification != want[f.Key.Asset] {
			t.Errorf("open finding on %v classification = %v, want %v", f.Key.Asset, f.Values.Classification, want[f.Key.Asset])
		}
	}
}

func TestModel3ScoresKeepTheExploitSignalAndTheClassificationMultiplier(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	id, _ := saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	cvss, epss := 8.1, 0.02
	in := scoring.Inputs{
		CVSS: &cvss, EPSS: &epss, Criticality: inventory.CriticalityHigh, Classification: inventory.ClassifiedPrivate,
		Exposure: inventory.Internal, Lifecycle: inventory.LifecycleProduction,
	}
	classified, err := scoring.Model3.Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Classification = inventory.Unclassified
	unclassified, err := scoring.Model3.Compute(in)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []scoring.Score{classified, unclassified} {
		inTx(t, w.db, func(tx *postgres.Tx) error {
			if stored, err := tx.SaveScoreIfChanged(context.Background(), id, want); err != nil || !stored {
				t.Fatalf("save %+v stored = %t, %v, want stored", want, stored, err)
			}
			latest, err := tx.LatestScore(context.Background(), id)
			if !reflect.DeepEqual(latest.Factors, want.Factors) || !slices.Equal(latest.Gaps, want.Gaps) {
				t.Errorf("latest score = %+v, want %+v", latest, want)
			}
			return err
		})
		open := inTxValue(t, w.db, func(tx *postgres.Tx) ([]postgres.CustomerFinding, error) {
			return tx.OpenFindingsOfCustomer(context.Background(), w.customer)
		})
		if len(open) != 1 || !reflect.DeepEqual(open[0].Score.Factors, want.Factors) {
			t.Errorf("open findings = %+v, want one with the factors %+v", open, want.Factors)
		}
	}
}

func TestSaveScoreIfChangedStoresOnlyAChangedScore(t *testing.T) {
	t.Parallel()
	w := newFindingWorld(t)
	id, _ := saveMatch(t, w.db, match(t, w.payments, "1.18.0"))
	score := scoring.Score{
		Model: 1, Value: 0.308,
		Factors: scoring.Factors{
			Alpha: 0.81, Beta: 0.9, Gamma: 0, Vulnerability: 0.513,
			CriticalityMultiplier: 1, ExposureMultiplier: 0.6, LifecycleMultiplier: 1,
		},
	}
	nextModel := score
	nextModel.Model = 2
	withGap := nextModel
	withGap.Gaps = []scoring.DataGap{scoring.ExposureUndeclared, scoring.LifecycleUnknown}

	for i, step := range []struct {
		score  scoring.Score
		stored bool
	}{
		{score, true},
		{score, false},
		{nextModel, true},
		{nextModel, false},
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
