-- name: InsertSyncRun :exec
INSERT INTO sync_runs (
    cmdb_source_id, started_at, finished_at, outcome_id,
    created, updated, deactivated, reactivated, skipped, skipped_records, failure
) VALUES (
    @cmdb_source_id, @started_at, @finished_at, @outcome_id,
    @created, @updated, @deactivated, @reactivated, @skipped, @skipped_records, @failure
);

-- name: SucceededRunStartedAfter :one
SELECT EXISTS (
    SELECT 1
    FROM sync_runs
    WHERE cmdb_source_id = @cmdb_source_id AND outcome_id = @outcome_id AND started_at > @started_at
);

-- name: LatestSyncRun :one
SELECT finished_at, outcome_id, failure
FROM sync_runs
WHERE cmdb_source_id = @cmdb_source_id
ORDER BY started_at DESC
LIMIT 1;

-- name: LatestSyncRunFinishedWithOutcome :one
SELECT finished_at
FROM sync_runs
WHERE cmdb_source_id = @cmdb_source_id AND outcome_id = @outcome_id
ORDER BY started_at DESC
LIMIT 1;
