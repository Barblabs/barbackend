package agents_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/claude/claudetest"
	"barbackend/internal/postgres"
)

const (
	labeledCVE  = "CVE-2026-116238"
	description = "In server mode pgAdmin 4 locks an internal account after 3 failed logins. The limit could be bypassed, giving an unauthenticated attacker an unlimited number of password guesses against any internal account, including the administrator's."
	guessQuote  = "an unlimited number of password guesses"
	accountsQ   = "against any internal account, including the administrator's"
)

// cartografoEnv is a database with a stored ATT&CK catalog and the
// Vulnerability of labeledCVE.
func cartografoEnv(t *testing.T, catalog bool) env {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	err := e.db.InTx(ctx, func(tx *postgres.Tx) error {
		object := `{"type":"vulnerability","spec_version":"2.1","id":"vulnerability--48ddf16e-0c34-5fd4-aeeb-1f1fc8027213",` +
			`"created":"2026-11-10T03:52:06.164Z","modified":"2026-11-10T03:52:06.164Z","name":"` + labeledCVE + `","description":"` + description + `"}`
		if err := tx.StoreVulnerability(ctx, postgres.StoredVulnerability{CVE: labeledCVE, Object: json.RawMessage(object), Modified: time.Now()}); err != nil {
			return err
		}
		if !catalog {
			return nil
		}
		for i, tech := range []struct{ id, name, tactic string }{
			{"T1078", "Valid Accounts", "initial-access"},
			{"T1110.001", "Password Guessing", "credential-access"},
		} {
			if err := tx.StoreAttackTechnique(ctx, postgres.AttackTechnique{
				ID: "attack-pattern--00000000-0000-4000-8000-00000000000" + string(rune('1'+i)), AttackID: tech.id, Name: tech.name,
				Tactics: []string{tech.tactic}, Object: json.RawMessage(`{}`), Modified: time.Now(),
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func labels(techniques ...map[string]any) map[string]any {
	return map[string]any{"techniques": techniques}
}

func technique(attackID, role, evidence string) map[string]any {
	return map[string]any{"attack_id": attackID, "role": role, "evidence": evidence, "rationale": "Encaja con el CVE."}
}

func labelingOf(t *testing.T, e env) postgres.Labeling {
	t.Helper()
	var l postgres.Labeling
	if err := e.db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		l, err = tx.LabelingOf(context.Background(), labeledCVE)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return l
}

func runCartografo(t *testing.T, e env) agents.LabelingRun {
	t.Helper()
	run, err := e.svc.LabelVulnerabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func TestTheCartografoLabelsAStoredVulnerability(t *testing.T) {
	t.Parallel()
	e := cartografoEnv(t, true)
	e.llm.Queue(claudetest.JSON(t, labels(
		technique("T1110.001", "exploitation", guessQuote),
		technique("T1078", "primary_impact", accountsQ),
	)))

	if run := runCartografo(t, e); run != (agents.LabelingRun{Labeled: 1}) {
		t.Errorf("run = %+v, want one labeled", run)
	}
	var got []postgres.TechniqueLabel
	if err := e.db.InTx(context.Background(), func(tx *postgres.Tx) (err error) {
		got, err = tx.TechniquesOf(context.Background(), labeledCVE)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].AttackID != "T1110.001" || got[0].Evidence != guessQuote || got[1].AttackID != "T1078" {
		t.Errorf("techniques = %+v, want T1110.001 then T1078 with their quotes", got)
	}
	if l := labelingOf(t, e); l.Outcome != postgres.LabelingLabeled || l.Model != "claude-haiku-5-5" || l.PromptHash == "" {
		t.Errorf("labeling = %+v, want labeled by claude-haiku-5-5 with its prompt hash", l)
	}
}

func TestTheCartografoSendsTheCatalogCachedAndTheVulnerabilityAsData(t *testing.T) {
	t.Parallel()
	e := cartografoEnv(t, true)
	e.llm.Queue(claudetest.JSON(t, labels()))

	runCartografo(t, e)

	request := e.llm.Requests()[0]
	content := request["messages"].([]any)[0].(map[string]any)["content"].([]any)
	catalog := content[0].(map[string]any)
	if !strings.Contains(catalog["text"].(string), "T1110.001 | Password Guessing | credential-access") || catalog["cache_control"] == nil {
		t.Errorf("first block = %v, want the catalog, cached", catalog)
	}
	prompt := content[len(content)-1].(map[string]any)["text"].(string)
	if !strings.HasPrefix(prompt, "<vulnerability>") || !strings.Contains(prompt, `"cve": "`+labeledCVE+`"`) {
		t.Errorf("prompt = %s, want the vulnerability in its tags", prompt)
	}
	if system := request["system"].([]any)[0].(map[string]any)["text"].(string); strings.Contains(system, labeledCVE) {
		t.Error("the system prompt holds feed data, which goes in the user message (ADR 0010)")
	}
}

func TestTheCartografoAnsweringNoTechniquesIsAFinalNone(t *testing.T) {
	t.Parallel()
	e := cartografoEnv(t, true)
	e.llm.Queue(claudetest.JSON(t, labels()))

	if run := runCartografo(t, e); run != (agents.LabelingRun{None: 1}) {
		t.Errorf("run = %+v, want one none", run)
	}
	if run := runCartografo(t, e); run != (agents.LabelingRun{}) || len(e.llm.Requests()) != 1 {
		t.Errorf("second run = %+v after %d requests, want nothing to label: a Labeling is paid once", run, len(e.llm.Requests()))
	}
}

func TestTheCartografoIsToldWhatFailedAndARejectedAnswerIsAFailedAttempt(t *testing.T) {
	t.Parallel()
	e := cartografoEnv(t, true)
	invented := labels(technique("T1059", "exploitation", "an attacker can run any command they like"))
	e.llm.Queue(claudetest.JSON(t, invented), claudetest.JSON(t, invented))

	if run := runCartografo(t, e); run != (agents.LabelingRun{Failed: 1}) {
		t.Errorf("run = %+v, want one failed", run)
	}
	requests := e.llm.Requests()
	if len(requests) != 2 {
		t.Fatalf("%d requests, want the answer and one retry", len(requests))
	}
	retry := requests[1]["messages"].([]any)[0].(map[string]any)["content"].([]any)
	if prompt := retry[len(retry)-1].(map[string]any)["text"].(string); !strings.Contains(prompt, "<rejected>") || !strings.Contains(prompt, "not a technique of the catalog") {
		t.Errorf("retry prompt = %s, want what was wrong in <rejected>", prompt)
	}
	if l := labelingOf(t, e); l.Outcome != postgres.LabelingFailed || l.Attempts != 1 {
		t.Errorf("labeling = %+v, want one failed attempt", l)
	}
}

func TestAFailedLabelingIsTriedInLaterRunsUpToThreeTimes(t *testing.T) {
	t.Parallel()
	e := cartografoEnv(t, true)
	for range 3 {
		e.llm.Queue(claudetest.Refusal())
		runCartografo(t, e)
	}

	if run := runCartografo(t, e); run != (agents.LabelingRun{}) {
		t.Errorf("fourth run = %+v, want nothing: no attempts left", run)
	}
	if l := labelingOf(t, e); l.Outcome != postgres.LabelingFailed || l.Attempts != 3 || len(e.llm.Requests()) != 3 {
		t.Errorf("labeling = %+v after %d requests, want 3 failed attempts", l, len(e.llm.Requests()))
	}
}

func TestTheCartografoWithoutACatalogLabelsNothing(t *testing.T) {
	t.Parallel()
	e := cartografoEnv(t, false)

	if run := runCartografo(t, e); run != (agents.LabelingRun{}) || len(e.llm.Requests()) != 0 {
		t.Errorf("run = %+v after %d requests, want nothing asked", run, len(e.llm.Requests()))
	}
	err := e.db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.LabelingOf(context.Background(), labeledCVE)
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("labeling err = %v, want none stored: no attempt is spent", err)
	}
}
