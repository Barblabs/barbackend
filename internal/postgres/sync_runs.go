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

// SyncStatus is what a person needs to judge how fresh a CMDB Source's
// Assets are.
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
