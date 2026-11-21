package agents_test

import (
	"context"
	"testing"

	"barbackend/internal/agents"
	"barbackend/internal/assessment"
	"barbackend/internal/finding"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

func TestFindingHistoryTellsWhatMovedEachFindingAndWhy(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := context.Background()
	p := e.prioritize(t)
	if _, err := e.svc.RecordFeedback(ctx, e.user, p.ID, e.os(), "should_be_earlier", "corre la nómina"); err != nil {
		t.Fatal(err)
	}
	e.rescore(t, e.os(), score(0.95))
	e.prioritizeWith(t, placement(newGroup("Ahora primero", e.os(), "Ubuntu Server 22.04 subió.", osEvidence(e)), standing(1)))
	history := func(id string) []agents.HistoryEntry {
		t.Helper()
		h, err := e.svc.FindingHistory(ctx, e.user, id)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}

	os := history(e.os())
	if len(os) != 2 || os[1].Kind != assessment.Placed || os[1].GroupNow != 2 || os[1].Title != "Después" {
		t.Fatalf("Ubuntu's history = %+v, want placed in Después, then placed again", os)
	}
	again := os[0]
	if again.Kind != assessment.PlacedAgain || again.GroupBefore != 2 || again.GroupNow != 1 || again.Title != "Ahora primero" ||
		again.Reason != "Ubuntu Server 22.04 subió."+gapsNamed || !again.Change.ScoreMoved || again.Change.ScoreTo != 0.95 {
		t.Errorf("Ubuntu placed again = %+v", again)
	}
	if len(again.Feedback) != 1 || again.Feedback[0].Verdict != "should_be_earlier" || again.Feedback[0].Note != "corre la nómina" {
		t.Errorf("feedback = %+v, want the User's word on the order", again.Feedback)
	}
	if pg := history(e.pg()); len(pg) != 2 || pg[0].Kind != assessment.Moved || pg[0].GroupBefore != 1 || pg[0].GroupNow != 2 ||
		len(pg[0].GroupsAppeared) != 1 || pg[0].GroupsAppeared[0] != "Ahora primero" || pg[0].Title != "Explotada activamente" {
		t.Errorf("PostgreSQL's history = %+v, want it moved down under Ahora primero", pg)
	}

	err := e.db.InTx(ctx, func(tx *postgres.Tx) error {
		_, err := tx.CloseFindingByHand(ctx, e.customer, finding.ID(uuid.MustParse(e.os())), postgres.ManualClose{Reason: finding.FalsePositive, By: e.user.ID(), Note: "solo en el laboratorio"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e.rescore(t, e.pg(), score(0.2))
	e.prioritizeWith(t, placement(newGroup("Al final", e.pg(), "PostgreSQL 15.6 bajó.", pgEvidence(e))))

	if os := history(e.os()); len(os) != 3 || os[0].Kind != assessment.Left || os[0].CloseReason != "false_positive" || os[0].GroupBefore != 1 {
		t.Errorf("Ubuntu's history after closing = %+v, want it left as a false positive", os)
	}
}
