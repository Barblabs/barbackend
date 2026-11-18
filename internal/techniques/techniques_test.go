package techniques_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/techniques"
	"github.com/TcM1911/stix2"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

const stamp = `"spec_version":"2.1","created":"2018-04-18T17:59:24.739Z","modified":"2026-05-12T15:12:00.628Z"`

// pattern is the STIX id of the Technique of that ATT&CK id in these tests.
func pattern(attackID string) string {
	ids := map[string]string{
		"T1190": "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c",
		"T1100": "attack-pattern--c16e5409-ee53-4d79-afdc-4099dc9292df",
		"T1300": "attack-pattern--e6a1b2c3-d4e5-4f60-8a71-b2c3d4e5f607",
	}
	return ids[attackID]
}

const m1051 = "course-of-action--e5d930e9-775a-40ad-9bdb-b941d8dfe86b"

// catalog decodes raw STIX objects as the ATT&CK adapter emits them.
func catalog(t *testing.T, raws ...string) []stix2.STIXObject {
	t.Helper()
	var out []stix2.STIXObject
	for _, raw := range raws {
		c, err := stix2.FromJSON([]byte("[" + raw + "]"))
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range c.AttackPatterns() {
			out = append(out, o)
		}
		for _, o := range c.CourseOfActions() {
			out = append(out, o)
		}
		for _, o := range c.Relationships() {
			out = append(out, o)
		}
	}
	return out
}

// techniqueJSON is a Technique; extra holds more of its properties, such as
// "revoked":true, each followed by a comma.
func techniqueJSON(attackID, name, extra string) string {
	return fmt.Sprintf(`{"type":"attack-pattern","id":%q,%s,"name":%q,%s
	 "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"initial-access"}],
	 "external_references":[{"source_name":"mitre-attack","external_id":%q}]}`, pattern(attackID), stamp, name, extra, attackID)
}

func relationshipJSON(n int, typ, source, target, description string) string {
	return fmt.Sprintf(`{"type":"relationship","id":"relationship--0005fb3b-274a-4ac1-8fb2-51366fcd1a%02d",%s,
	 "relationship_type":%q,"source_ref":%q,"target_ref":%q,"description":%q}`, n, stamp, typ, source, target, description)
}

var mitigationJSON = `{"type":"course-of-action","id":"` + m1051 + `",` + stamp + `,"name":"Update Software",
 "external_references":[{"source_name":"mitre-attack","external_id":"M1051"}]}`

func handle(t *testing.T, batch []stix2.STIXObject) *postgres.DB {
	t.Helper()
	db := pgtest.NewDB(t)
	if err := techniques.New(db).HandleATTACK(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	return db
}

func read(t *testing.T, db *postgres.DB, attackID string) postgres.LabeledTechnique {
	t.Helper()
	const cve = "CVE-2099-0001"
	threats, err := postgres.InTxValue(context.Background(), db, func(tx *postgres.Tx) (map[string]postgres.Threats, error) {
		ctx := context.Background()
		if err := tx.StoreVulnerability(ctx, postgres.StoredVulnerability{CVE: cve, Object: json.RawMessage(`{"type":"vulnerability"}`), Modified: time.Now()}); err != nil {
			return nil, err
		}
		label := postgres.TechniqueLabel{AttackID: attackID, Role: "exploitation", Evidence: "e", Rationale: "r"}
		if err := tx.StoreLabeling(ctx, cve, "model", "hash", []postgres.TechniqueLabel{label}); err != nil {
			return nil, err
		}
		return tx.ThreatsOf(ctx, []string{cve})
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(threats[cve].Techniques) != 1 {
		t.Fatalf("techniques = %+v, want the one labeled", threats[cve].Techniques)
	}
	return threats[cve].Techniques[0]
}

func current(t *testing.T, db *postgres.DB, attackID string) postgres.AttackTechnique {
	t.Helper()
	got := read(t, db, attackID)
	if got.Current == nil {
		t.Fatalf("%s is not in the catalog", attackID)
	}
	return *got.Current
}

func TestATechniqueIsStoredWithItsTacticsAndMitigations(t *testing.T) {
	t.Parallel()
	db := handle(t, catalog(t,
		relationshipJSON(1, "mitigates", m1051, pattern("T1190"), "Update software regularly."),
		techniqueJSON("T1190", "Exploit Public-Facing Application", ""),
		mitigationJSON,
	))

	got := read(t, db, "T1190")
	if got.Current == nil || got.Current.AttackID != "T1190" || got.Current.Revoked || got.Current.Deprecated {
		t.Fatalf("T1190 = %+v, want the current Technique itself", got.Current)
	}
	if len(got.Current.Tactics) != 1 || got.Current.Tactics[0] != "initial-access" {
		t.Errorf("tactics = %v, want initial-access", got.Current.Tactics)
	}
	want := postgres.TechniqueMitigation{AttackID: "M1051", Name: "Update Software", Advice: "Update software regularly."}
	if len(got.Mitigations) != 1 || got.Mitigations[0] != want {
		t.Errorf("mitigations = %+v, want %+v", got.Mitigations, want)
	}
}

func TestARevokedTechniqueIsReadAsItsReplacement(t *testing.T) {
	t.Parallel()
	db := handle(t, catalog(t,
		relationshipJSON(1, "revoked-by", pattern("T1100"), pattern("T1190"), ""),
		techniqueJSON("T1100", "Revoked", `"revoked":true,`),
		techniqueJSON("T1190", "Exploit Public-Facing Application", ""),
	))

	if got := current(t, db, "T1100"); got.AttackID != "T1190" || got.Revoked {
		t.Errorf("T1100 = %+v, want its replacement T1190", got)
	}
}

func TestADeprecatedTechniqueIsReadMarked(t *testing.T) {
	t.Parallel()
	db := handle(t, catalog(t, techniqueJSON("T1300", "Deprecated", `"x_mitre_deprecated":true,`)))

	if got := current(t, db, "T1300"); !got.Deprecated {
		t.Errorf("T1300 = %+v, want it marked deprecated", got)
	}
}
