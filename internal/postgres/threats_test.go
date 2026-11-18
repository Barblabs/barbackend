package postgres_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"barbackend/internal/assessment"
	"barbackend/internal/postgres"
)

const t1505ID = "attack-pattern--5d0d3609-d06d-49e1-b9c9-b544e0c618cb"

// storeCatalog stores T1190 with M1051, and T1100 revoked by T1505.003, which
// has M1016.
func storeCatalog(t *testing.T, db *postgres.DB) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error {
		ctx := context.Background()
		for _, technique := range []postgres.AttackTechnique{technique(t1190ID, "T1190", "Exploit Public-Facing Application", may), revoked(t1100ID, "T1100", "Web Shell"), technique(t1505ID, "T1505.003", "Web Shell", may)} {
			if err := tx.StoreAttackTechnique(ctx, technique); err != nil {
				return err
			}
		}
		for _, m := range []postgres.AttackMitigation{mitigation(m1051ID, "M1051", "Update Software"), mitigation(m1016ID, "M1016", "Vulnerability Scanning")} {
			if err := tx.StoreAttackMitigation(ctx, m); err != nil {
				return err
			}
		}
		for _, r := range []postgres.AttackRelationship{
			relationship("relationship--0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", "mitigates", m1051ID, t1190ID, "Update the software."),
			relationship("relationship--1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e", "mitigates", m1016ID, t1505ID, "Scan for web shells."),
			relationship("relationship--2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f", "revoked-by", t1100ID, t1505ID, ""),
		} {
			if err := tx.StoreAttackRelationship(ctx, r); err != nil {
				return err
			}
		}
		return nil
	})
}

func TestThreatsOfReadsWhatIsStoredAboutEachVulnerability(t *testing.T) {
	t.Parallel()
	const labeled, failed, untried = "CVE-2025-1094", "CVE-2024-6387", "CVE-2021-23017"
	db := storedCVEs(t, labeled, failed, untried)
	storeCatalog(t, db)
	for i, published := range []time.Time{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)} {
		id := []string{"report--8d4f0bd1-4a71-4b77-a2a6-0b9c3b1c6d01", "report--8d4f0bd1-4a71-4b77-a2a6-0b9c3b1c6d02"}[i]
		storeAdvisory(t, db, postgres.StoredAdvisory{ID: id, Feed: "aws", Published: published, Object: json.RawMessage(`{"type":"report"}`), Modified: published}, labeled)
	}
	if err := storeLabeling(db, labeled,
		postgres.TechniqueLabel{AttackID: "T9999", Role: "secondary_impact", Evidence: "it says so somewhere", Rationale: "r"},
		postgres.TechniqueLabel{AttackID: "T1100", Role: "primary_impact", Evidence: "it says so somewhere", Rationale: "r"},
		postgres.TechniqueLabel{AttackID: "T1190", Role: "exploitation", Evidence: "it says so somewhere", Rationale: "r"},
	); err != nil {
		t.Fatal(err)
	}
	if err := storeFailedLabeling(db, failed); err != nil {
		t.Fatal(err)
	}

	got := inTxValue(t, db, func(tx *postgres.Tx) (map[string]postgres.Threats, error) {
		return tx.ThreatsOf(context.Background(), []string{labeled, failed, untried})
	})

	threats := got[labeled]
	if len(threats.Advisories) != 2 || !threats.Advisories[0].Published.After(threats.Advisories[1].Published) {
		t.Errorf("advisories = %+v, want both, newest first", threats.Advisories)
	}
	if threats.Labeling == nil || threats.Labeling.Outcome != assessment.LabelingLabeled || len(threats.Techniques) != 3 {
		t.Fatalf("labeled = %+v", threats)
	}
	exploitation, impact, unknown := threats.Techniques[0], threats.Techniques[1], threats.Techniques[2]
	if exploitation.Label.AttackID != "T1190" || exploitation.Current.AttackID != "T1190" || len(exploitation.Mitigations) != 1 || exploitation.Mitigations[0].Advice != "Update the software." {
		t.Errorf("exploitation = %+v", exploitation)
	}
	if impact.Label.AttackID != "T1100" || impact.Current.AttackID != "T1505.003" || len(impact.Mitigations) != 1 || impact.Mitigations[0].AttackID != "M1016" {
		t.Errorf("revoked label = %+v, want it read as T1505.003 with its Mitigation", impact)
	}
	if unknown.Label.AttackID != "T9999" || unknown.Current != nil || len(unknown.Mitigations) != 0 {
		t.Errorf("label the catalog does not hold = %+v", unknown)
	}
	if f := got[failed]; f.Labeling == nil || f.Labeling.Outcome != assessment.LabelingFailed || len(f.Techniques) != 0 || len(f.Advisories) != 0 {
		t.Errorf("failed = %+v", f)
	}
	if u := got[untried]; u.Labeling != nil || u.Techniques != nil || u.Advisories != nil {
		t.Errorf("not tried = %+v, want nothing", u)
	}
}

func labeledAs(t *testing.T, attackID string, relationships ...postgres.AttackRelationship) postgres.LabeledTechnique {
	t.Helper()
	const cve = "CVE-2099-0001"
	db := storedCVEs(t, cve)
	inTx(t, db, func(tx *postgres.Tx) error {
		ctx := context.Background()
		for _, technique := range []postgres.AttackTechnique{
			revoked(t1100ID, "T1100", "Revoked first"), revoked(t1200ID, "T1200", "Revoked later"),
			technique(t1190ID, "T1190", "Exploit Public-Facing Application", may),
		} {
			if err := tx.StoreAttackTechnique(ctx, technique); err != nil {
				return err
			}
		}
		for _, r := range relationships {
			if err := tx.StoreAttackRelationship(ctx, r); err != nil {
				return err
			}
		}
		return nil
	})
	if err := storeLabeling(db, cve, postgres.TechniqueLabel{AttackID: attackID, Role: "exploitation", Evidence: "it says so somewhere", Rationale: "r"}); err != nil {
		t.Fatal(err)
	}
	threats := inTxValue(t, db, func(tx *postgres.Tx) (map[string]postgres.Threats, error) {
		return tx.ThreatsOf(context.Background(), []string{cve})
	})
	if len(threats[cve].Techniques) != 1 || threats[cve].Techniques[0].Current == nil {
		t.Fatalf("techniques = %+v, want the one labeled, in the catalog", threats[cve].Techniques)
	}
	return threats[cve].Techniques[0]
}

func TestALabelIsReadAsItsCurrentTechnique(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		relationships []postgres.AttackRelationship
		wantAttackID  string
		wantRevoked   bool
	}{
		{
			name: "replaced twice",
			relationships: []postgres.AttackRelationship{
				relationship("relationship--0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", "revoked-by", t1100ID, t1200ID, ""),
				relationship("relationship--1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e", "revoked-by", t1200ID, t1190ID, ""),
			},
			wantAttackID: "T1190",
		},
		{name: "revoked with no replacement", wantAttackID: "T1100", wantRevoked: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := labeledAs(t, "T1100", tt.relationships...).Current
			if got.AttackID != tt.wantAttackID || got.Revoked != tt.wantRevoked {
				t.Errorf("T1100 = %+v, want %s with revoked %v", got, tt.wantAttackID, tt.wantRevoked)
			}
		})
	}
}

func TestReadingALabelStopsOnARevocationCycle(t *testing.T) {
	t.Parallel()
	got := labeledAs(t, "T1100",
		relationship("relationship--0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", "revoked-by", t1100ID, t1200ID, ""),
		relationship("relationship--1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e", "revoked-by", t1200ID, t1100ID, ""),
	)

	if !got.Current.Revoked {
		t.Errorf("T1100 = %+v, want a revoked Technique after the bounded walk", got.Current)
	}
}

func TestTechniquesOfCVEsReadEachLabelAsItsCurrentTechnique(t *testing.T) {
	t.Parallel()
	const labeled, failed = "CVE-2025-1094", "CVE-2024-6387"
	db := storedCVEs(t, labeled, failed)
	storeCatalog(t, db)
	if err := storeLabeling(db, labeled,
		postgres.TechniqueLabel{AttackID: "T9999", Role: "secondary_impact", Evidence: "it says so somewhere", Rationale: "r"},
		postgres.TechniqueLabel{AttackID: "T1100", Role: "primary_impact", Evidence: "it says so somewhere", Rationale: "r"},
		postgres.TechniqueLabel{AttackID: "T1190", Role: "exploitation", Evidence: "it says so somewhere", Rationale: "r"},
	); err != nil {
		t.Fatal(err)
	}
	if err := storeFailedLabeling(db, failed); err != nil {
		t.Fatal(err)
	}

	got := inTxValue(t, db, func(tx *postgres.Tx) (map[string][]postgres.CVETechnique, error) {
		return tx.TechniquesOfCVEs(context.Background(), []string{labeled, failed})
	})

	techniques := got[labeled]
	if len(got) != 1 || len(techniques) != 2 {
		t.Fatalf("techniques = %+v, want two of the labeled CVE, and none for the one the catalog does not hold", got)
	}
	if e := techniques[0]; e.Role != "exploitation" || e.Technique.AttackID != "T1190" || len(e.Technique.Tactics) != 1 {
		t.Errorf("first = %+v, want T1190 exploiting it, with its tactic", e)
	}
	if i := techniques[1]; i.Role != "primary_impact" || i.Technique.AttackID != "T1505.003" {
		t.Errorf("second = %+v, want revoked T1100 read as T1505.003", i)
	}
}
