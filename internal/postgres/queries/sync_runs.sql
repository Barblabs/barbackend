-- name: InsertSyncRun :exec
INSERT INTO sync_runs (
    cmdb_source_id, started_at, finished_at, outcome_id,
    created, updated, deactivated, reactivated, skipped, skipped_records, error
) VALUES (
    @cmdb_source_id, @started_at, @finished_at, @outcome_id,
    @created, @updated, @deactivated, @reactivated, @skipped, @skipped_records, @error
);
