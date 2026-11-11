package techniques_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

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
		"T1200": "attack-pattern--d456de47-a16f-4e46-8980-e67478a12dcb",
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

func newService(t *testing.T, batch []stix2.STIXObject) *techniques.Service {
	t.Helper()
	s := techniques.New(pgtest.NewDB(t))
	if err := s.HandleATTACK(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	return s
}

func read(t *testing.T, s *techniques.Service, attackID string) techniques.Resolved {
	t.Helper()
	r, err := s.Technique(context.Background(), attackID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTechniqueIsReadWithItsTacticsAndMitigations(t *testing.T) {
	t.Parallel()
	s := newService(t, catalog(t,
		relationshipJSON(1, "mitigates", m1051, pattern("T1190"), "Update software regularly."),
		techniqueJSON("T1190", "Exploit Public-Facing Application", ""),
		mitigationJSON,
	))

	got := read(t, s, " t1190 ")
	if got.AttackID != "T1190" || got.Replaced() || got.Revoked || got.Deprecated {
		t.Errorf("T1190 = %+v, want the current Technique itself", got)
	}
	if len(got.Tactics) != 1 || got.Tactics[0] != "initial-access" {
		t.Errorf("tactics = %v, want initial-access", got.Tactics)
	}
	want := techniques.Mitigation{AttackID: "M1051", Name: "Update Software", Advice: "Update software regularly."}
	if len(got.Mitigations) != 1 || got.Mitigations[0] != want {
		t.Errorf("mitigations = %+v, want %+v", got.Mitigations, want)
	}
}

func TestARevokedTechniqueIsReadAsItsCurrentReplacement(t *testing.T) {
	t.Parallel()
	s := newService(t, catalog(t,
		techniqueJSON("T1100", "Revoked first", `"revoked":true,`),
		techniqueJSON("T1200", "Revoked later", `"revoked":true,`),
		techniqueJSON("T1190", "Exploit Public-Facing Application", ""),
		relationshipJSON(1, "revoked-by", pattern("T1100"), pattern("T1200"), ""),
		relationshipJSON(2, "revoked-by", pattern("T1200"), pattern("T1190"), ""),
	))

	got := read(t, s, "T1100")
	if got.AttackID != "T1190" || got.Asked != "T1100" || !got.Replaced() || got.Revoked {
		t.Errorf("T1100 = %+v, want T1190, two replacements later, asked as T1100", got)
	}
}

func TestARevokedTechniqueWithNoReplacementIsReadMarked(t *testing.T) {
	t.Parallel()
	s := newService(t, catalog(t, techniqueJSON("T1100", "Revoked", `"revoked":true,`)))

	if got := read(t, s, "T1100"); got.AttackID != "T1100" || !got.Revoked {
		t.Errorf("T1100 = %+v, want it as it is, marked revoked", got)
	}
}

func TestADeprecatedTechniqueIsReadMarked(t *testing.T) {
	t.Parallel()
	s := newService(t, catalog(t, techniqueJSON("T1300", "Deprecated", `"x_mitre_deprecated":true,`)))

	if got := read(t, s, "T1300"); !got.Deprecated {
		t.Errorf("T1300 = %+v, want it marked deprecated", got)
	}
}

func TestReadingStopsOnARevocationCycle(t *testing.T) {
	t.Parallel()
	s := newService(t, catalog(t,
		techniqueJSON("T1100", "Revoked", `"revoked":true,`),
		techniqueJSON("T1200", "Revoked too", `"revoked":true,`),
		relationshipJSON(1, "revoked-by", pattern("T1100"), pattern("T1200"), ""),
		relationshipJSON(2, "revoked-by", pattern("T1200"), pattern("T1100"), ""),
	))

	if got := read(t, s, "T1100"); !got.Revoked {
		t.Errorf("T1100 = %+v, want a revoked Technique after the bounded walk", got)
	}
}

func TestAnUnknownTechniqueIsNotFound(t *testing.T) {
	t.Parallel()
	s := newService(t, nil)

	if _, err := s.Technique(context.Background(), "T9999"); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
