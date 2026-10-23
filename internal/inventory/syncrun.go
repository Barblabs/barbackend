package inventory

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

var ErrInvalidSyncRun = errors.New("invalid sync run")

type SyncOutcome int16

const (
	SyncSucceeded SyncOutcome = 1
	SyncFailed    SyncOutcome = 2
)

func (o SyncOutcome) String() string {
	switch o {
	case SyncSucceeded:
		return "Succeeded"
	case SyncFailed:
		return "Failed"
	default:
		return fmt.Sprintf("SyncOutcome(%d)", int(o))
	}
}

// SyncRun records one Sync of a CMDB Source. A failed run changed no Asset,
// so it has no counts and skipped no records.
type SyncRun struct {
	source   CMDBSourceID
	started  time.Time
	finished time.Time
	outcome  SyncOutcome
	counts   SyncCounts
	skipped  []SkippedRecord
	failure  string
}

func SucceededRun(r Reconciliation, started, finished time.Time) (SyncRun, error) {
	if err := validateRun(r.source, started, finished); err != nil {
		return SyncRun{}, err
	}
	return SyncRun{
		source:   r.source,
		started:  started,
		finished: finished,
		outcome:  SyncSucceeded,
		counts:   r.Counts(),
		skipped:  r.Skipped(),
	}, nil
}

func FailedRun(source CMDBSourceID, started, finished time.Time, cause error) (SyncRun, error) {
	if err := validateRun(source, started, finished); err != nil {
		return SyncRun{}, err
	}
	if cause == nil {
		return SyncRun{}, fmt.Errorf("%w: failed without an error", ErrInvalidSyncRun)
	}
	return SyncRun{source: source, started: started, finished: finished, outcome: SyncFailed, failure: cause.Error()}, nil
}

func validateRun(source CMDBSourceID, started, finished time.Time) error {
	switch {
	case source == CMDBSourceID{}:
		return fmt.Errorf("%w: zero source", ErrInvalidSyncRun)
	case started.IsZero() || finished.IsZero():
		return fmt.Errorf("%w: missing start or finish time", ErrInvalidSyncRun)
	case finished.Before(started):
		return fmt.Errorf("%w: finished before it started", ErrInvalidSyncRun)
	}
	return nil
}

func (r SyncRun) Source() CMDBSourceID { return r.source }

func (r SyncRun) Started() time.Time { return r.started }

func (r SyncRun) Finished() time.Time { return r.finished }

func (r SyncRun) Outcome() SyncOutcome { return r.outcome }

func (r SyncRun) Counts() SyncCounts { return r.counts }

func (r SyncRun) Skipped() []SkippedRecord { return slices.Clone(r.skipped) }

// Failure is the error a failed run stopped on, empty for a successful run.
func (r SyncRun) Failure() string { return r.failure }
