package attack_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"barbackend/internal/feeds/attack"
	"github.com/TcM1911/stix2"
)

const (
	t1190   = "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c"
	t1100   = "attack-pattern--c16e5409-ee53-4d79-afdc-4099dc9292df"
	t1505   = "attack-pattern--d456de47-a16f-4e46-8980-e67478a12dcb"
	m1051   = "course-of-action--e5d930e9-775a-40ad-9bdb-b941d8dfe86b"
	group   = "intrusion-set--bef4c620-0787-42a8-a96d-b7eb6e85917c"
	group2  = "intrusion-set--c93fccb1-e8e8-42cf-ae33-2ad1d183913a"
	malware = "malware--d1531eaa-9e17-473e-a680-3298469662c3"
	stamp   = `"created":"2018-04-18T17:59:24.739Z","modified":"2026-05-12T15:12:00.628Z","spec_version":"2.1"`
)

// bundle has one object of each kind the adapter keeps, and one of each kind
// it drops.
var bundle = `{"type":"bundle","id":"bundle--1d2c3b4a-5f6e-4d7c-8b9a-0a1b2c3d4e5f","objects":[
 {"type":"attack-pattern","id":"` + t1190 + `",` + stamp + `,"name":"Exploit Public-Facing Application",
  "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"initial-access"}],
  "x_mitre_platforms":["Linux","Windows"],"x_mitre_deprecated":false,
  "external_references":[{"source_name":"mitre-attack","external_id":"T1190"}]},
 {"type":"attack-pattern","id":"` + t1100 + `",` + stamp + `,"name":"Web Shell","revoked":true,
  "external_references":[{"source_name":"mitre-attack","external_id":"T1100"}]},
 {"type":"attack-pattern","id":"` + t1505 + `",` + stamp + `,"name":"No ATT&CK id"},
 {"type":"course-of-action","id":"` + m1051 + `",` + stamp + `,"name":"Update Software",
  "external_references":[{"source_name":"mitre-attack","external_id":"M1051"}]},
 {"type":"course-of-action","id":"course-of-action--4f170666-7edb-4489-85c2-9affa28a72e0",` + stamp + `,"name":"Old mitigation","x_mitre_deprecated":true,
  "external_references":[{"source_name":"mitre-attack","external_id":"T1190"}]},
 {"type":"relationship","id":"relationship--0005fb3b-274a-4ac1-8fb2-51366fcd1a6b",` + stamp + `,"relationship_type":"mitigates",
  "description":"Update software regularly.","source_ref":"` + m1051 + `","target_ref":"` + t1190 + `"},
 {"type":"relationship","id":"relationship--1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",` + stamp + `,"relationship_type":"revoked-by",
  "source_ref":"` + t1100 + `","target_ref":"` + t1505 + `"},
 {"type":"relationship","id":"relationship--2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e",` + stamp + `,"relationship_type":"revoked-by",
  "source_ref":"` + group + `","target_ref":"` + group2 + `"},
 {"type":"relationship","id":"relationship--3c4d5e6f-7a8b-4c9d-8e1f-2a3b4c5d6e7f",` + stamp + `,"relationship_type":"uses",
  "source_ref":"` + group + `","target_ref":"` + t1190 + `"},
 {"type":"malware","id":"` + malware + `",` + stamp + `,"name":"Some malware","is_family":true}
]}`

func pull(t *testing.T) []stix2.STIXObject {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(bundle)) }))
	t.Cleanup(srv.Close)
	var got []stix2.STIXObject
	if err := attack.New(srv.Client(), srv.URL).Pull(context.Background(), func(o stix2.STIXObject) error {
		got = append(got, o)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func ids(objs []stix2.STIXObject) []string {
	out := make([]string, len(objs))
	for i, o := range objs {
		out[i] = string(o.GetID())
	}
	return out
}

func TestPullKeepsTechniquesMitigationsAndTheirRelationships(t *testing.T) {
	t.Parallel()
	got := ids(pull(t))
	want := []string{
		t1190, t1100, m1051,
		"relationship--0005fb3b-274a-4ac1-8fb2-51366fcd1a6b",
		"relationship--1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
	}
	if !slices.Equal(got, want) {
		t.Errorf("emitted %v, want %v", got, want)
	}
}

func TestPullDropsWhatADR0023DoesNotKeep(t *testing.T) {
	t.Parallel()
	got := ids(pull(t))
	for _, dropped := range []string{
		t1505, // no ATT&CK id
		"course-of-action--4f170666-7edb-4489-85c2-9affa28a72e0", // the old T form
		"relationship--2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e",     // revoked-by between groups
		"relationship--3c4d5e6f-7a8b-4c9d-8e1f-2a3b4c5d6e7f",     // uses
		malware,
	} {
		if slices.Contains(got, dropped) {
			t.Errorf("emitted %s, want it dropped", dropped)
		}
	}
}

func TestPullKeepsTheATTACKPropertiesOfATechnique(t *testing.T) {
	t.Parallel()
	technique := pull(t)[0]
	encoded, err := json.Marshal(technique)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Platforms []string `json:"x_mitre_platforms"`
		Phases    []struct {
			Phase string `json:"phase_name"`
		} `json:"kill_chain_phases"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(decoded.Platforms, []string{"Linux", "Windows"}) {
		t.Errorf("x_mitre_platforms = %v, want them kept when the Technique is stored", decoded.Platforms)
	}
	if len(decoded.Phases) != 1 || decoded.Phases[0].Phase != "initial-access" {
		t.Errorf("kill_chain_phases = %+v, want initial-access", decoded.Phases)
	}
}

func TestPullKeepsTheAdviceOfAMitigatesRelationship(t *testing.T) {
	t.Parallel()
	for _, o := range pull(t) {
		r, ok := o.(*stix2.Relationship)
		if ok && r.RelationshipType == stix2.RelationshipTypeMitigates {
			if r.Description != "Update software regularly." || string(r.Source) != m1051 || string(r.Target) != t1190 {
				t.Errorf("mitigates = %+v, want M1051 to T1190 with its advice", r)
			}
			return
		}
	}
	t.Fatal("no mitigates relationship emitted")
}
