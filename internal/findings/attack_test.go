package findings_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"barbackend/internal/findings"
)

// labeledWorld is countedWorld with T1190, T1068 and T1499 in the ATT&CK
// catalog, and nginx's CVE labeled with T1190 exploiting it and T1499 as its
// primary impact. OpenSSL's CVE has no Labeling.
func labeledWorld(t *testing.T) world {
	t.Helper()
	w := countedWorld(t)
	for i, technique := range []struct{ attackID, name, tactic string }{
		{"T1190", "Exploit Public-Facing Application", "initial-access"},
		{"T1068", "Exploitation for Privilege Escalation", "privilege-escalation"},
		{"T1499", "Endpoint Denial of Service", "impact"},
	} {
		w.exec(t, `INSERT INTO attack_techniques (id, attack_id, name, tactics, revoked, deprecated, object, modified_at)
			VALUES ($1, $2, $3, ARRAY[$4::text], false, false, '{}', now())`,
			fmt.Sprintf("attack-pattern--00000000-0000-4000-8000-00000000000%d", i), technique.attackID, technique.name, technique.tactic)
	}
	w.exec(t, `INSERT INTO vulnerability_labelings (cve_id, outcome, attempts, model, prompt_hash) VALUES ('CVE-2021-23017', 'labeled', 1, 'm', 'h')`)
	w.exec(t, `INSERT INTO vulnerability_techniques (cve_id, attack_id, role, evidence, rationale) VALUES
		('CVE-2021-23017', 'T1190', 'exploitation', 'e', 'r'), ('CVE-2021-23017', 'T1499', 'primary_impact', 'e', 'r')`)
	return w
}

func TestAttackMatrixCountsFindingsByTheTacticsAndTechniquesOfTheirCVE(t *testing.T) {
	t.Parallel()
	w := labeledWorld(t)

	m, err := w.findings.AttackMatrix(context.Background(), w.viewer(t), "", 0)
	if err != nil {
		t.Fatal(err)
	}

	if m.Open != 3 || m.Labeled != 2 {
		t.Errorf("coverage = %d of %d, want 2 of 3", m.Labeled, m.Open)
	}
	nginx := findings.BandCounts{Critical: 1, High: 1}
	wantTactics := []findings.TacticCount{{Tactic: "initial-access", Bands: nginx}, {Tactic: "privilege-escalation"}, {Tactic: "impact", Bands: nginx}}
	if fmt.Sprint(m.Tactics) != fmt.Sprint(wantTactics) {
		t.Errorf("tactics = %+v, want %+v", m.Tactics, wantTactics)
	}
	if len(m.Techniques) != 2 || m.Techniques[0].AttackID != "T1190" || m.Techniques[1].AttackID != "T1499" {
		t.Fatalf("techniques = %+v, want T1190 then T1499, and no T1068 without Findings", m.Techniques)
	}
	if first := m.Techniques[0]; first.Bands != nginx || fmt.Sprint(first.Roles) != "[exploitation]" || first.Name != "Exploit Public-Facing Application" {
		t.Errorf("T1190 = %+v", first)
	}
}

func TestAttackMatrixCountsOnlyTheLabelsOfARole(t *testing.T) {
	t.Parallel()
	w := labeledWorld(t)

	m, err := w.findings.AttackMatrix(context.Background(), w.viewer(t), findings.RoleExploitation, 0)
	if err != nil {
		t.Fatal(err)
	}

	if m.Labeled != 2 || m.Tactics[2].Bands.Total() != 0 || len(m.Techniques) != 1 || m.Techniques[0].AttackID != "T1190" {
		t.Errorf("matrix = %+v, want only T1190 and its tactic counted, and the coverage of any role", m)
	}
	if _, err := w.findings.AttackMatrix(context.Background(), w.viewer(t), "lateral", 0); !errors.Is(err, findings.ErrInvalidCount) {
		t.Errorf("unknown role: err = %v, want ErrInvalidCount", err)
	}
	if _, err := w.findings.AttackMatrix(context.Background(), w.viewer(t), "", findings.MaxTopLimit+1); !errors.Is(err, findings.ErrInvalidCount) {
		t.Errorf("limit %d: err = %v, want ErrInvalidCount", findings.MaxTopLimit+1, err)
	}
}
