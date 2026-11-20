package findings_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/findings"
	"barbackend/internal/inventory"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func TestCloseByHandClosesAFindingThatALaterMatchHolds(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	viewer := w.storedUser(t, "viewer@example.com", tenancy.Viewer)
	changed := 0
	w.findings.OnChanged(func() { changed++ })
	_, _, _, scores := w.latestScore(t, f.id)

	if err := w.findings.CloseByHand(context.Background(), viewer, finding.ID(f.id), finding.FalsePositive, "  only in the lab  ", nil); err != nil {
		t.Fatal(err)
	}
	if got := w.mustFinding(t, "payments", "CVE-2021-23017"); got.open || got.closeReason != "false_positive" {
		t.Fatalf("finding = %+v, want closed as false_positive", got)
	}
	if changed != 1 {
		t.Errorf("changed = %d, want 1", changed)
	}

	w.afterSync(t, server(t, "payments", inventory.CriticalityLow, app("Nginx", "f5", "nginx", "1.19.0")))
	got := w.mustFinding(t, "payments", "CVE-2021-23017")
	if got.open || got.version != "1.19.0" {
		t.Errorf("finding after a Sync = %+v, want held closed at 1.19.0", got)
	}
	if _, _, _, after := w.latestScore(t, f.id); after != scores {
		t.Errorf("scores = %d, want %d: a held Finding is not rescored", after, scores)
	}
}

func TestCloseByHandRejectsAnInvalidClose(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	viewer := w.storedUser(t, "viewer@example.com", tenancy.Viewer)
	ahead, past := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)
	tests := []struct {
		name     string
		reason   finding.CloseReason
		note     string
		reopenAt *time.Time
	}{
		{name: "a reason only a match gives", reason: finding.ComponentRemoved, note: "gone"},
		{name: "a blank note", reason: finding.FalsePositive, note: "   "},
		{name: "a note too long", reason: finding.FalsePositive, note: strings.Repeat("a", findings.MaxCloseNoteLength+1)},
		{name: "an accepted risk without reopen time", reason: finding.AcceptedRisk, note: "known"},
		{name: "a false positive with a reopen time", reason: finding.FalsePositive, note: "lab", reopenAt: &ahead},
		{name: "a reopen time already past", reason: finding.Postponed, note: "later", reopenAt: &past},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := w.findings.CloseByHand(context.Background(), viewer, finding.ID(f.id), tt.reason, tt.note, tt.reopenAt)
			if !errors.Is(err, findings.ErrInvalidClose) {
				t.Errorf("err = %v, want ErrInvalidClose", err)
			}
		})
	}
	if !w.mustFinding(t, "payments", "CVE-2021-23017").open {
		t.Error("an invalid close closed the Finding")
	}
}

func TestCloseByHandFailsOnAFindingNotOpenInTheCustomer(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	viewer := w.storedUser(t, "viewer@example.com", tenancy.Viewer)
	other := newWorld(t).storedUser(t, "other@example.com", tenancy.Viewer)
	ctx := context.Background()

	if err := w.findings.CloseByHand(ctx, other, finding.ID(f.id), finding.FalsePositive, "lab", nil); !errors.Is(err, findings.ErrFindingNotFound) {
		t.Errorf("another Customer's close = %v, want ErrFindingNotFound", err)
	}
	if err := w.findings.CloseByHand(ctx, viewer, finding.ID(f.id), finding.Remediated, "patched", nil); err != nil {
		t.Fatal(err)
	}
	if err := w.findings.CloseByHand(ctx, viewer, finding.ID(f.id), finding.FalsePositive, "lab", nil); !errors.Is(err, findings.ErrFindingClosed) {
		t.Errorf("second close = %v, want ErrFindingClosed", err)
	}
}

func TestReopenByHandReopensOnlyAFindingAUserClosed(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	admin := w.storedUser(t, "admin@example.com", tenancy.CustomerAdmin)
	ctx := context.Background()
	id := finding.ID(f.id)

	if err := w.findings.ReopenByHand(ctx, admin, id); !errors.Is(err, findings.ErrNotClosedByHand) {
		t.Errorf("reopen of an open Finding = %v, want ErrNotClosedByHand", err)
	}
	if err := w.findings.ReopenByHand(ctx, admin, finding.ID(uuid.New())); !errors.Is(err, findings.ErrFindingNotFound) {
		t.Errorf("reopen of an unknown Finding = %v, want ErrFindingNotFound", err)
	}
	reopenAt := time.Now().Add(30 * 24 * time.Hour)
	if err := w.findings.CloseByHand(ctx, admin, id, finding.AcceptedRisk, "behind the WAF", &reopenAt); err != nil {
		t.Fatal(err)
	}
	if err := w.findings.ReopenByHand(ctx, admin, id); err != nil {
		t.Fatal(err)
	}
	if got := w.mustFinding(t, "payments", "CVE-2021-23017"); !got.open {
		t.Errorf("finding = %+v, want open", got)
	}
	if n := w.count(t, `SELECT count(*) FROM findings WHERE closed_by IS NOT NULL OR close_note IS NOT NULL OR reopen_at IS NOT NULL`); n != 0 {
		t.Errorf("%d Findings keep a close after reopening", n)
	}

	w.afterSync(t, server(t, "payments", inventory.CriticalityHigh))
	if got := w.mustFinding(t, "payments", "CVE-2021-23017"); got.closeReason != "component_removed" {
		t.Fatalf("finding = %+v, want closed as component_removed", got)
	}
	if err := w.findings.ReopenByHand(ctx, admin, id); !errors.Is(err, findings.ErrNotClosedByHand) {
		t.Errorf("reopen of a Finding closed on its own = %v, want ErrNotClosedByHand", err)
	}
}

func TestClosedByHandListsOnlyWhatUsersClosedNewestFirst(t *testing.T) {
	t.Parallel()
	w := countedWorld(t)
	viewer := w.storedUser(t, "viewer@example.com", tenancy.Viewer)
	ctx := context.Background()
	a := w.mustFinding(t, "a", "CVE-2021-23017")
	b := w.mustFinding(t, "b", "CVE-2021-23017")
	reopenAt := time.Now().Add(7 * 24 * time.Hour)
	if err := w.findings.CloseByHand(ctx, viewer, finding.ID(a.id), finding.FalsePositive, "lab copy", nil); err != nil {
		t.Fatal(err)
	}
	if err := w.findings.CloseByHand(ctx, viewer, finding.ID(b.id), finding.Postponed, "next sprint", &reopenAt); err != nil {
		t.Fatal(err)
	}
	w.afterSync(t, server(t, "a", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")))
	if got := w.mustFinding(t, "a", opensslCVE); got.open {
		t.Fatalf("OpenSSL's finding = %+v, want closed on its own", got)
	}

	closed, err := w.findings.ClosedByHand(ctx, viewer)
	if err != nil {
		t.Fatal(err)
	}
	if len(closed) != 2 {
		t.Fatalf("closed = %+v, want the two closed by hand, not OpenSSL's closed on its own", closed)
	}
	if got := closed[0]; got.ID != finding.ID(b.id) || got.AssetName != "server b" || got.Reason != finding.Postponed ||
		got.Note != "next sprint" || got.ReopenAt == nil || got.ClosedByEmail != "viewer@example.com" || got.CVE != "CVE-2021-23017" {
		t.Errorf("newest = %+v, want b's postponed one", got)
	}
	if got := closed[1]; got.ID != finding.ID(a.id) || got.Reason != finding.FalsePositive || got.ReopenAt != nil {
		t.Errorf("oldest = %+v, want a's false positive", got)
	}
	if other, err := w.findings.ClosedByHand(ctx, newWorld(t).storedUser(t, "other@example.com", tenancy.Viewer)); err != nil || len(other) != 0 {
		t.Errorf("another Customer's = %+v, %v, want none", other, err)
	}
}
