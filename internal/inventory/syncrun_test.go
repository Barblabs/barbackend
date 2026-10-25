package inventory_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"barbackend/internal/inventory"
)

func TestSucceededRun(t *testing.T) {
	started := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	finished := started.Add(time.Minute)
	s := snapshot(t, recs("1", validParams()), "2")
	r, err := inventory.Reconcile(sourceID, nil, s)
	if err != nil {
		t.Fatal(err)
	}

	run, err := inventory.SucceededRun(r, started, finished)
	if err != nil {
		t.Fatal(err)
	}
	if run.Source() != sourceID || run.Outcome() != inventory.SyncSucceeded || run.Failure() != "" {
		t.Errorf("run = %+v, want a successful run of %v", run, sourceID)
	}
	if !run.Started().Equal(started) || !run.Finished().Equal(finished) {
		t.Errorf("started, finished = %v, %v; want %v, %v", run.Started(), run.Finished(), started, finished)
	}
	if want := (inventory.SyncCounts{Created: 1, Skipped: 1}); run.Counts() != want {
		t.Errorf("Counts() = %+v, want %+v", run.Counts(), want)
	}
	if !reflect.DeepEqual(run.Skipped(), s.Skipped) {
		t.Errorf("Skipped() = %+v, want %+v", run.Skipped(), s.Skipped)
	}
}

func TestSucceededRunRejectsZeroReconciliation(t *testing.T) {
	started := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	if _, err := inventory.SucceededRun(inventory.Reconciliation{}, started, started); !errors.Is(err, inventory.ErrInvalidSyncRun) {
		t.Errorf("err = %v, want ErrInvalidSyncRun", err)
	}
}

func TestFailedRun(t *testing.T) {
	started := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	cause := errors.New("cmdb unreachable")
	tests := []struct {
		name     string
		source   inventory.CMDBSourceID
		started  time.Time
		finished time.Time
		cause    error
		want     error
	}{
		{"valid", sourceID, started, started, cause, nil},
		{"zero source", inventory.CMDBSourceID{}, started, started, cause, inventory.ErrInvalidSyncRun},
		{"zero start", sourceID, time.Time{}, started, cause, inventory.ErrInvalidSyncRun},
		{"zero finish", sourceID, started, time.Time{}, cause, inventory.ErrInvalidSyncRun},
		{"finished before started", sourceID, started, started.Add(-time.Second), cause, inventory.ErrInvalidSyncRun},
		{"no cause", sourceID, started, started, nil, inventory.ErrInvalidSyncRun},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run, err := inventory.FailedRun(tt.source, tt.started, tt.finished, tt.cause)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if err != nil {
				return
			}
			if run.Outcome() != inventory.SyncFailed || run.Failure() != cause.Error() {
				t.Errorf("outcome, failure = %v, %q; want Failed, %q", run.Outcome(), run.Failure(), cause.Error())
			}
			if run.Counts() != (inventory.SyncCounts{}) || run.Skipped() != nil {
				t.Errorf("counts, skipped = %+v, %+v; want none", run.Counts(), run.Skipped())
			}
		})
	}
}
