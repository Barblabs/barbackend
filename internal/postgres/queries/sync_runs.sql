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

-- Every day from the one starting at since to the one starting at last_start,
-- each 24 hours long: how many Syncs of every CMDB Source finished in it,
-- succeeded or not.
-- name: CountSyncRunsByDay :many
SELECT d.start::timestamptz AS day,
       (SELECT count(*) FROM sync_runs r
        WHERE r.outcome_id = @succeeded_outcome_id
          AND r.finished_at >= d.start AND r.finished_at < d.start + interval '24 hours')::integer AS succeeded,
       (SELECT count(*) FROM sync_runs r
        WHERE r.outcome_id <> @succeeded_outcome_id
          AND r.finished_at >= d.start AND r.finished_at < d.start + interval '24 hours')::integer AS failed
FROM generate_series(@since::timestamptz, @last_start::timestamptz, interval '24 hours') AS d(start)
ORDER BY d.start;
