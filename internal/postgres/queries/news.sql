-- Stores a News Item on receipt, or replaces it when its Feed published it
-- again (ADR 0025). A ready one, a leak post, is ready from the first time it
-- is stored; being stored again never changes when it became ready.
-- name: UpsertNewsItem :exec
INSERT INTO news_items (id, feed, kind, published_at, cve_ids, object, modified_at, ready_at)
VALUES (@id, @feed, @kind, @published_at, @cve_ids::text[], @object, @modified_at,
        CASE WHEN @ready::boolean THEN now() END)
ON CONFLICT (id) DO UPDATE
SET feed = EXCLUDED.feed,
    published_at = EXCLUDED.published_at,
    cve_ids = EXCLUDED.cve_ids,
    object = EXCLUDED.object,
    modified_at = EXCLUDED.modified_at;

-- Stores a victim a structured Feed names, or replaces it.
-- name: UpsertNewsVictim :exec
INSERT INTO news_victims (id, object)
VALUES (@id, @object)
ON CONFLICT (id) DO UPDATE
SET object = EXCLUDED.object;

-- Links a News Item to the stored victims among those it refers to.
-- name: LinkNewsVictims :exec
INSERT INTO news_item_victims (news_item_id, victim_id)
SELECT @news_item_id, v.id
FROM news_victims v
WHERE v.id = ANY(@victim_ids::text[])
ON CONFLICT (news_item_id, victim_id) DO NOTHING;

-- The articles the Reader should read: published since a moment, with no
-- reading, or with a failed one that has attempts left, newest first.
-- name: ListUnreadArticles :many
SELECT n.id, n.object
FROM news_items n
LEFT JOIN news_readings r ON r.news_item_id = n.id
WHERE n.kind = 'article'
  AND n.ready_at IS NULL
  AND n.published_at >= @published_since
  AND (r.news_item_id IS NULL OR (r.outcome = 'failed' AND r.attempts < @max_attempts::integer))
ORDER BY n.published_at DESC, n.id
LIMIT @max_items::integer;

-- Records an attempt to read a News Item. A read one is final and is left as
-- it is; a failed one counts one more attempt. It returns the attempts, and
-- no row when the reading was already final.
-- name: RecordReading :one
INSERT INTO news_readings (news_item_id, outcome, attempts, model, prompt_id, content)
VALUES (@news_item_id, @outcome, 1, @model, @prompt_id, @content)
ON CONFLICT (news_item_id) DO UPDATE
SET outcome = EXCLUDED.outcome,
    attempts = news_readings.attempts + 1,
    model = EXCLUDED.model,
    prompt_id = EXCLUDED.prompt_id,
    content = EXCLUDED.content,
    read_at = now()
WHERE news_readings.outcome = 'failed'
RETURNING attempts;

-- Makes a News Item ready for News Digests, once.
-- name: MarkNewsItemReady :exec
UPDATE news_items
SET ready_at = now()
WHERE id = @id AND ready_at IS NULL;

-- How many readings were attempted since a moment, so the Reader's daily cap
-- holds across restarts of serve. A reading counts once, at its last attempt.
-- name: CountReadingsSince :one
SELECT count(*)::integer
FROM news_readings
WHERE read_at >= @since;

-- The News Items that became ready in (since, until], with their reading
-- when the Reader read them.
-- name: ListReadyNewsItems :many
SELECT n.id, n.object, r.content AS reading
FROM news_items n
LEFT JOIN news_readings r ON r.news_item_id = n.id AND r.outcome = 'read'
WHERE n.ready_at > @since AND n.ready_at <= @until
ORDER BY n.published_at DESC, n.id;

-- The victims of some News Items.
-- name: ListVictimsOfNewsItems :many
SELECT l.news_item_id, v.object
FROM news_item_victims l
JOIN news_victims v ON v.id = l.victim_id
WHERE l.news_item_id = ANY(@news_item_ids::text[])
ORDER BY l.news_item_id, v.id;

-- The open Findings of a Customer, by CVE and Asset name.
-- name: ListOpenFindingCVEsOfCustomer :many
SELECT DISTINCT f.cve_id, a.name AS asset_name
FROM findings f
JOIN assets a ON a.cmdb_source_id = f.cmdb_source_id AND a.record_id = f.record_id
JOIN cmdb_sources s ON s.id = f.cmdb_source_id
WHERE s.customer_id = @customer_id AND f.closed_at IS NULL
ORDER BY f.cve_id, a.name;

-- The Products the Active Assets of a Customer run, by Asset name.
-- name: ListProductsOfCustomer :many
SELECT DISTINCT lower(c.product_vendor) AS product_vendor, lower(c.product_name) AS product_name, a.name AS asset_name
FROM software_components c
JOIN assets a ON a.cmdb_source_id = c.cmdb_source_id AND a.record_id = c.record_id
JOIN cmdb_sources s ON s.id = c.cmdb_source_id
WHERE s.customer_id = @customer_id
  AND a.inactive_since IS NULL
  AND c.product_vendor IS NOT NULL AND c.product_name IS NOT NULL
ORDER BY 1, 2, 3;

-- name: InsertNewsDigest :exec
INSERT INTO news_digests (id, customer_id, since, until, business_context_version,
                          named_count, finding_count, footprint_count, peer_count, content)
VALUES (@id, @customer_id, @since, @until, @business_context_version,
        @named_count, @finding_count, @footprint_count, @peer_count, @content);

-- When the Customer's newest News Digest ends.
-- name: LatestNewsDigestUntil :one
SELECT until
FROM news_digests
WHERE customer_id = @customer_id
ORDER BY until DESC
LIMIT 1;

-- The Customer's News Digests, newest first.
-- name: ListNewsDigests :many
SELECT id, since, until, named_count, finding_count, footprint_count, peer_count, created_at
FROM news_digests
WHERE customer_id = @customer_id
ORDER BY created_at DESC, id
LIMIT @max_digests::integer;

-- name: GetNewsDigest :one
SELECT id, since, until, business_context_version, named_count, finding_count, footprint_count, peer_count, content, created_at
FROM news_digests
WHERE customer_id = @customer_id AND id = @id;
