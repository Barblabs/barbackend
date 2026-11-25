package findings_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/findings"
	"barbackend/internal/inventory"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

var closesNow = time.Date(2026, time.November, 25, 12, 0, 0, 0, time.UTC)

var openedLongAgo = closesNow.AddDate(0, 0, -100)

func nginxWorld(t *testing.T, records ...string) world {
	t.Helper()
	w := newWorld(t)
	servers := make([]inventory.Record, len(records))
	for i, r := range records {
		servers[i] = server(t, r, inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0"))
	}
	w.sync(t, servers...)
	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201))
	for _, r := range records {
		w.setHistory(t, r, openedLongAgo, time.Time{})
	}
	w.findings.SetNow(func() time.Time { return closesNow })
	return w
}

func (w world) closeAs(t *testing.T, record string, reason finding.CloseReason, opened, closed time.Time) {
	t.Helper()
	var closedBy, note, reopenAt any
	if reason.ByHand() {
		closedBy = uuid.UUID(w.storedUser(t, record+"@example.com", tenancy.Viewer).ID())
		note = "why"
	}
	if reason.Expires() {
		reopenAt = closed.AddDate(1, 0, 0)
	}
	w.exec(t, `
		UPDATE findings
		SET opened_at = $1, closed_at = $2, close_reason_id = $3, closed_by = $4, close_note = $5, reopen_at = $6
		WHERE record_id = $7`, opened, closed, int16(reason), closedBy, note, reopenAt, record)
}

func TestClosesCountsEachReasonInItsBucket(t *testing.T) {
	t.Parallel()
	inWindow := closesNow.AddDate(0, 0, -1)
	justBefore := closesNow.AddDate(0, 0, -findings.DefaultClosesDays).Add(-time.Hour)
	tests := []struct {
		reason finding.CloseReason
		closed time.Time
		want   findings.Closes
	}{
		{finding.Remediated, inWindow, findings.Closes{Current: findings.CloseCounts{Fixed: 1}}},
		{finding.ComponentRemoved, inWindow, findings.Closes{Current: findings.CloseCounts{Fixed: 1}}},
		{finding.NoLongerAffected, inWindow, findings.Closes{Current: findings.CloseCounts{Fixed: 1}}},
		{finding.AssetInactive, inWindow, findings.Closes{Current: findings.CloseCounts{WentAway: 1}}},
		{finding.VulnerabilityRejected, inWindow, findings.Closes{Current: findings.CloseCounts{WentAway: 1}}},
		{finding.VulnerabilityRevised, inWindow, findings.Closes{Current: findings.CloseCounts{WentAway: 1}}},
		{finding.AcceptedRisk, inWindow, findings.Closes{Current: findings.CloseCounts{SetAside: 1}}},
		{finding.Postponed, inWindow, findings.Closes{Current: findings.CloseCounts{SetAside: 1}}},
		{finding.FalsePositive, inWindow, findings.Closes{Current: findings.CloseCounts{SetAside: 1}}},
		{finding.Remediated, justBefore, findings.Closes{Previous: findings.CloseCounts{Fixed: 1}}},
	}
	for _, tt := range tests {
		t.Run(tt.reason.String()+" "+tt.closed.Format(time.DateOnly), func(t *testing.T) {
			t.Parallel()
			w := nginxWorld(t, "a")
			w.closeAs(t, "a", tt.reason, openedLongAgo, tt.closed)

			got, err := w.findings.Closes(context.Background(), w.viewer(t), 0)
			if err != nil {
				t.Fatal(err)
			}

			if got.Current != tt.want.Current || got.Previous != tt.want.Previous {
				t.Errorf("closes = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestClosesCountsFirstOpensButNotReopens(t *testing.T) {
	t.Parallel()
	w := nginxWorld(t, "new", "reopened", "earlier")
	w.setHistory(t, "new", closesNow.AddDate(0, 0, -2), time.Time{})
	w.exec(t, `UPDATE findings SET opened_at = $1 WHERE record_id = 'reopened'`, closesNow.AddDate(0, 0, -2))
	w.setHistory(t, "earlier", closesNow.AddDate(0, 0, -40), time.Time{})

	got, err := w.findings.Closes(context.Background(), w.viewer(t), 0)
	if err != nil {
		t.Fatal(err)
	}

	if got.Current.Opened != 1 || got.Previous.Opened != 1 {
		t.Errorf("opened = %d now and %d before, want 1 and 1", got.Current.Opened, got.Previous.Opened)
	}
}

func TestClosesTakesTheMedianDaysToFixOnlyOfCriticalFixedFindingsInTheWindow(t *testing.T) {
	t.Parallel()
	w := nginxWorld(t, "2d", "4d", "8d", "10d", "high", "went-away", "before")
	closed := closesNow.AddDate(0, 0, -1)
	for record, days := range map[string]int{"2d": 2, "4d": 4, "8d": 8, "10d": 10, "high": 1} {
		w.closeAs(t, record, finding.Remediated, closed.AddDate(0, 0, -days), closed)
	}
	w.closeAs(t, "went-away", finding.AssetInactive, closed.AddDate(0, 0, -1), closed)
	w.closeAs(t, "before", finding.Remediated, closesNow.AddDate(0, 0, -41), closesNow.AddDate(0, 0, -40))
	for _, record := range []string{"2d", "4d", "8d", "10d", "went-away", "before"} {
		w.setScore(t, record, "CVE-2021-23017", 0.9)
	}
	w.setScore(t, "high", "CVE-2021-23017", 0.5)

	got, err := w.findings.Closes(context.Background(), w.viewer(t), 0)
	if err != nil {
		t.Fatal(err)
	}

	if got.CriticalFixedMedianDays == nil || *got.CriticalFixedMedianDays != 6 {
		t.Errorf("critical fixed median days = %v, want 6: between 4d and 8d", got.CriticalFixedMedianDays)
	}
}

func TestClosesLeavesOutAnotherCustomersFindings(t *testing.T) {
	t.Parallel()
	w := nginxWorld(t, "a", "b")
	w.setHistory(t, "a", closesNow.AddDate(0, 0, -2), time.Time{})
	w.closeAs(t, "b", finding.Remediated, closesNow.AddDate(0, 0, -2), closesNow.AddDate(0, 0, -1))
	w.setScore(t, "b", "CVE-2021-23017", 0.9)
	other := w
	other.customer = tenancy.CustomerID(uuid.New())
	w.exec(t, `INSERT INTO customers (id, name) VALUES ($1, 'other')`, uuid.UUID(other.customer))

	got, err := w.findings.Closes(context.Background(), other.viewer(t), 0)
	if err != nil {
		t.Fatal(err)
	}

	if got != (findings.Closes{}) {
		t.Errorf("another Customer's closes = %+v, want none", got)
	}
}

func TestClosesRefusesDaysOutOfRange(t *testing.T) {
	t.Parallel()
	w := newWorld(t)

	for _, days := range []int{-1, findings.MaxClosesDays + 1} {
		if _, err := w.findings.Closes(context.Background(), w.viewer(t), days); !errors.Is(err, findings.ErrInvalidCloses) {
			t.Errorf("%d days: err = %v, want ErrInvalidCloses", days, err)
		}
	}
}
