package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// LatestSyncRuns is what a person needs to judge how fresh a CMDB Source's
// Assets are.
type LatestSyncRuns struct {
	// SucceededFinished is when the latest successful Sync Run finished, zero
	// if no Sync of the source succeeded.
	SucceededFinished time.Time
	// Latest is the latest Sync Run, by start, or nil if the source never synced.
	Latest *SyncRunEnd
}

// SyncRunEnd is how a Sync Run ended.
type SyncRunEnd struct {
	Outcome  inventory.SyncOutcome
	Finished time.Time
	// Failure is the error a failed run stopped on, empty for a successful run.
	Failure string
}

func (t *Tx) LatestSyncRuns(ctx context.Context, id inventory.CMDBSourceID) (LatestSyncRuns, error) {
	var runs LatestSyncRuns
	latest, err := t.q.LatestSyncRun(ctx, uuid.UUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return runs, nil
	}
	if err != nil {
		return LatestSyncRuns{}, fmt.Errorf("latest sync run of %s: %w", id, err)
	}
	runs.Latest = &SyncRunEnd{Outcome: inventory.SyncOutcome(latest.OutcomeID), Finished: latest.FinishedAt}
	if latest.Failure != nil {
		runs.Latest.Failure = *latest.Failure
	}
	runs.SucceededFinished, err = t.q.LatestSyncRunFinishedWithOutcome(ctx, sqlcgen.LatestSyncRunFinishedWithOutcomeParams{
		CmdbSourceID: uuid.UUID(id),
		OutcomeID:    int16(inventory.SyncSucceeded),
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return LatestSyncRuns{}, fmt.Errorf("latest successful sync run of %s: %w", id, err)
	}
	return runs, nil
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
	p := sqlcgen.InsertSyncRunParams{
		CmdbSourceID:   uuid.UUID(run.Source()),
		StartedAt:      run.Started(),
		FinishedAt:     run.Finished(),
		OutcomeID:      int16(run.Outcome()),
		Created:        int32(counts.Created),
		Updated:        int32(counts.Updated),
		Deactivated:    int32(counts.Deactivated),
		Reactivated:    int32(counts.Reactivated),
		Skipped:        int32(counts.Skipped),
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
