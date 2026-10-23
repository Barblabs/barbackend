package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RecordFailedSync records a Sync that changed no Asset. It refuses a
// succeeded run: those are recorded only by CommitSync, with their changes.
func (t *Tx) RecordFailedSync(ctx context.Context, run inventory.SyncRun) error {
	if run.Outcome() != inventory.SyncFailed {
		return fmt.Errorf("record failed sync of %s: run %s", run.Source(), run.Outcome())
	}
	return recordSyncRun(ctx, t.q, run)
}

type SyncStatus struct {
	// LastSync is when the latest successful Sync Run finished, zero if no
	// Sync of the source succeeded.
	LastSync time.Time
	// LastFailure is set only while the latest Sync Run is a failed one.
	LastFailure *SyncFailure
}

type SyncFailure struct {
	At    time.Time
	Error string
}

func (t *Tx) SyncStatus(ctx context.Context, id inventory.CMDBSourceID) (SyncStatus, error) {
	var status SyncStatus
	latest, err := t.q.LatestSyncRun(ctx, uuid.UUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return status, nil
	}
	if err != nil {
		return SyncStatus{}, fmt.Errorf("latest sync run of %s: %w", id, err)
	}
	if inventory.SyncOutcome(latest.OutcomeID) == inventory.SyncFailed {
		status.LastFailure = &SyncFailure{At: latest.FinishedAt}
		if latest.Failure != nil {
			status.LastFailure.Error = *latest.Failure
		}
	}
	status.LastSync, err = t.q.LatestSyncRunFinishedWithOutcome(ctx, sqlcgen.LatestSyncRunFinishedWithOutcomeParams{
		CmdbSourceID: uuid.UUID(id),
		OutcomeID:    int16(inventory.SyncSucceeded),
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return SyncStatus{}, fmt.Errorf("latest successful sync run of %s: %w", id, err)
	}
	return status, nil
}

type skippedRecord struct {
	RecordID string `json:"record_id"`
	Reason   string `json:"reason"`
}

func recordSyncRun(ctx context.Context, q *sqlcgen.Queries, run inventory.SyncRun) error {
	skipped := make([]skippedRecord, 0, len(run.Skipped()))
	for _, rej := range run.Skipped() {
		skipped = append(skipped, skippedRecord{RecordID: rej.RecordID, Reason: rej.Reason})
	}
	skippedJSON, err := json.Marshal(skipped)
	if err != nil {
		return fmt.Errorf("encode skipped records: %w", err)
	}
	counts := run.Counts()
	var created, updated, deactivated, reactivated, skippedCount int32
	for _, c := range []struct {
		dst *int32
		n   int
	}{
		{&created, counts.Created},
		{&updated, counts.Updated},
		{&deactivated, counts.Deactivated},
		{&reactivated, counts.Reactivated},
		{&skippedCount, counts.Skipped},
	} {
		if *c.dst, err = countColumn(c.n); err != nil {
			return fmt.Errorf("sync run of %s: %w", run.Source(), err)
		}
	}
	p := sqlcgen.InsertSyncRunParams{
		CmdbSourceID:   uuid.UUID(run.Source()),
		StartedAt:      run.Started(),
		FinishedAt:     run.Finished(),
		OutcomeID:      int16(run.Outcome()),
		Created:        created,
		Updated:        updated,
		Deactivated:    deactivated,
		Reactivated:    reactivated,
		Skipped:        skippedCount,
		SkippedRecords: skippedJSON,
	}
	if failure := run.Failure(); failure != "" {
		p.Failure = &failure
	}
	if err := q.InsertSyncRun(ctx, p); err != nil {
		return fmt.Errorf("insert sync run of %s: %w", run.Source(), err)
	}
	return nil
}

func countColumn(n int) (int32, error) {
	if n < 0 || n > math.MaxInt32 {
		return 0, fmt.Errorf("count %d does not fit an integer column", n)
	}
	return int32(n), nil
}
