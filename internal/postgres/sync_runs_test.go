package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

func TestSyncRunRoundTrip(t *testing.T) {
	started := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	type row struct {
		Started, Finished time.Time
		Outcome           int16
		Counts            [5]int
		Skipped           []inventory.SkippedRecord
		Error             *string
	}
	failure := "cmdb unreachable"
	tests := []struct {
		name   string
		record func(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID) inventory.SyncRun
		want   row
	}{
		{
			name: "succeeded",
			record: func(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID) inventory.SyncRun {
				run, err := db.CommitSync(context.Background(), src, started, reconcileWith(src, inventory.Snapshot{
					Records: []inventory.Record{{RecordID: "1", Imported: mustImported(t, fullParams(t))}},
					Skipped: []inventory.SkippedRecord{{RecordID: "2", Reason: "no name"}},
				}))
				if err != nil {
					t.Fatal(err)
				}
				return run
			},
			want: row{
				Outcome: int16(inventory.SyncSucceeded),
				Counts:  [5]int{1, 0, 0, 0, 1},
				Skipped: []inventory.SkippedRecord{{RecordID: "2", Reason: "no name"}},
			},
		},
		{
			name: "failed",
			record: func(t *testing.T, db *postgres.DB, src inventory.CMDBSourceID) inventory.SyncRun {
				run, err := inventory.FailedRun(src, started, started.Add(time.Minute), errors.New(failure))
				if err != nil {
					t.Fatal(err)
				}
				inTx(t, db, func(tx *postgres.Tx) error { return tx.RecordFailedSync(context.Background(), run) })
				return run
			},
			want: row{
				Outcome: int16(inventory.SyncFailed),
				Skipped: []inventory.SkippedRecord{}, Error: &failure,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, conn := newDBWithConn(t)
			src := newSource(t, db, newCustomer(t, db))

			run := tt.record(t, db, src.ID())

			var got row
			var skipped []byte
			err := conn.QueryRow(context.Background(), `
				SELECT started_at, finished_at, outcome_id, created, updated, deactivated, reactivated, skipped, skipped_records, failure
				FROM sync_runs WHERE cmdb_source_id = $1`, src.ID().String()).
				Scan(&got.Started, &got.Finished, &got.Outcome,
					&got.Counts[0], &got.Counts[1], &got.Counts[2], &got.Counts[3], &got.Counts[4], &skipped, &got.Error)
			if err != nil {
				t.Fatal(err)
			}
			var records []struct {
				RecordID string `json:"record_id"`
				Reason   string `json:"reason"`
			}
			if err := json.Unmarshal(skipped, &records); err != nil {
				t.Fatal(err)
			}
			// A JSON null instead of [] leaves records nil, so got.Skipped stays nil.
			if records != nil {
				got.Skipped = []inventory.SkippedRecord{}
			}
			for _, r := range records {
				got.Skipped = append(got.Skipped, inventory.SkippedRecord{RecordID: r.RecordID, Reason: r.Reason})
			}
			got.Started, got.Finished = got.Started.UTC(), got.Finished.UTC()
			want := tt.want
			want.Started, want.Finished = run.Started().UTC(), run.Finished().UTC()
			if !reflect.DeepEqual(got, want) {
				t.Errorf("row = %+v, want %+v", got, want)
			}
		})
	}
}

func TestRecordFailedSyncRejectsSucceededRun(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	src := newSource(t, db, newCustomer(t, db))
	r, err := inventory.Reconcile(src.ID(), inventory.Stored{}, inventory.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	run, err := inventory.SucceededRun(r, now, now)
	if err != nil {
		t.Fatal(err)
	}

	err = db.InTx(context.Background(), func(tx *postgres.Tx) error { return tx.RecordFailedSync(context.Background(), run) })

	if err == nil {
		t.Error("err = nil, want an error for a succeeded run")
	}
	if n := queryInt(t, conn, "SELECT count(*) FROM sync_runs"); n != 0 {
		t.Errorf("sync runs = %d, want 0", n)
	}
}

func TestSyncDaysCountEveryDayIncludingQuietOnes(t *testing.T) {
	t.Parallel()
	db, conn := newDBWithConn(t)
	src := newSource(t, db, newCustomer(t, db))
	since := time.Date(2026, time.November, 10, 0, 0, 0, 0, time.UTC)
	for _, run := range []struct {
		finished time.Time
		outcome  inventory.SyncOutcome
	}{
		{since.Add(30 * time.Hour), inventory.SyncSucceeded},
		{since.Add(40 * time.Hour), inventory.SyncSucceeded},
		{since.Add(50 * time.Hour), inventory.SyncFailed},
		{since.Add(-time.Hour), inventory.SyncFailed},
	} {
		if _, err := conn.Exec(context.Background(), `
			INSERT INTO sync_runs (cmdb_source_id, started_at, finished_at, outcome_id, created, updated, deactivated, reactivated, skipped, skipped_records)
			VALUES ($1, $2, $2, $3, 0, 0, 0, 0, 0, '[]')`, uuid.UUID(src.ID()), run.finished, int16(run.outcome)); err != nil {
			t.Fatal(err)
		}
	}

	days := inTxValue(t, db, func(tx *postgres.Tx) ([]postgres.SyncDay, error) {
		return tx.SyncDays(context.Background(), since, 3)
	})

	want := []postgres.SyncDay{{Start: since}, {Start: since.Add(24 * time.Hour), Succeeded: 2}, {Start: since.Add(48 * time.Hour), Failed: 1}}
	if len(days) != len(want) {
		t.Fatalf("days = %+v, want %+v", days, want)
	}
	for i := range want {
		if !days[i].Start.Equal(want[i].Start) || days[i].Succeeded != want[i].Succeeded || days[i].Failed != want[i].Failed {
			t.Errorf("day %d = %+v, want %+v", i, days[i], want[i])
		}
	}
}
