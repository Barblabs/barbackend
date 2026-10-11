package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"github.com/google/uuid"
)

func (t *Tx) RecordSyncRun(ctx context.Context, run inventory.SyncRun) error {
	return recordSyncRun(ctx, t.q, run)
}

// RecordSyncRun records a run in the transaction that saved its changes, so
// both commit or neither does.
func (t *SourceTx) RecordSyncRun(ctx context.Context, run inventory.SyncRun) error {
	// Only this transaction's CMDB Source is locked.
	if run.Source() != t.source {
		return fmt.Errorf("record in %s: sync run of %s", t.source, run.Source())
	}
	return recordSyncRun(ctx, t.q, run)
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
