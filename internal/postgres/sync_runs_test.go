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
)

func TestSyncRunRoundTrip(t *testing.T) {
	started := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	finished := started.Add(time.Minute)
	type row struct {
		Started, Finished time.Time
		Outcome           int16
		Counts            [5]int
		Skipped           []inventory.Rejection
		Error             *string
	}
	failure := "cmdb unreachable"
	tests := []struct {
		name string
		run  func(t *testing.T, src inventory.CMDBSourceID) inventory.SyncRun
		want row
	}{
		{
			name: "succeeded",
			run: func(t *testing.T, src inventory.CMDBSourceID) inventory.SyncRun {
				r, err := inventory.Reconcile(src, nil, inventory.Snapshot{
					Records:    []inventory.Record{{RecordID: "1", Imported: mustImported(t, fullParams(t))}},
					Rejections: []inventory.Rejection{{RecordID: "2", Reason: "no name"}},
				})
				if err != nil {
					t.Fatal(err)
				}
				run, err := inventory.SucceededRun(r, started, finished)
				if err != nil {
					t.Fatal(err)
				}
				return run
			},
			want: row{
				Started: started, Finished: finished, Outcome: int16(inventory.SyncSucceeded),
				Counts:  [5]int{1, 0, 0, 0, 1},
				Skipped: []inventory.Rejection{{RecordID: "2", Reason: "no name"}},
			},
		},
		{
			name: "failed",
			run: func(t *testing.T, src inventory.CMDBSourceID) inventory.SyncRun {
				run, err := inventory.FailedRun(src, started, finished, errors.New(failure))
				if err != nil {
					t.Fatal(err)
				}
				return run
			},
			want: row{
				Started: started, Finished: finished, Outcome: int16(inventory.SyncFailed),
				Skipped: []inventory.Rejection{}, Error: &failure,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db, conn := newDBWithConn(t)
			src := newSource(t, db, newCustomer())
			run := tt.run(t, src.ID())

			inTx(t, db, func(tx *postgres.Tx) error { return tx.RecordSyncRun(context.Background(), run) })

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
				got.Skipped = []inventory.Rejection{}
			}
			for _, r := range records {
				got.Skipped = append(got.Skipped, inventory.Rejection{RecordID: r.RecordID, Reason: r.Reason})
			}
			got.Started, got.Finished = got.Started.UTC(), got.Finished.UTC()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("row = %+v, want %+v", got, tt.want)
			}
		})
	}
}
