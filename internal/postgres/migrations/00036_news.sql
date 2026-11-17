-- +goose Up

-- News Items (ADR 0025): every article and leak-site post a news Feed
-- publishes, stored on receipt and shared by every Customer: they are public.
-- object is the STIX report as its Feed emitted it, and one published again
-- replaces it. ready_at is when it can go in a News Digest: on receipt for a
-- leak post, which comes with its victim; once the Reader's reading is final
-- for an article.
CREATE TABLE news_items (
    id           text PRIMARY KEY CHECK (id ~ '^report--[0-9a-f-]{36}$'),
    feed         text NOT NULL CHECK (length(feed) > 0),
    kind         text NOT NULL CHECK (kind IN ('article', 'leak_post')),
    published_at timestamptz NOT NULL,
    cve_ids      text[] NOT NULL,
    object       jsonb NOT NULL,
    modified_at  timestamptz NOT NULL,
    stored_at    timestamptz NOT NULL DEFAULT now(),
    ready_at     timestamptz
);
CREATE INDEX news_items_ready_idx ON news_items (ready_at) WHERE ready_at IS NOT NULL;
CREATE INDEX news_items_unready_idx ON news_items (published_at DESC) WHERE ready_at IS NULL;

-- The victims structured Feeds name (ADR 0010), one per STIX identity, so a
-- victim two posts claim is stored once.
CREATE TABLE news_victims (
    id        text PRIMARY KEY CHECK (id ~ '^identity--[0-9a-f-]{36}$'),
    object    jsonb NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE news_item_victims (
    news_item_id text NOT NULL REFERENCES news_items (id),
    victim_id    text NOT NULL REFERENCES news_victims (id),
    PRIMARY KEY (news_item_id, victim_id)
);

-- The Reader's reading of each article (ADR 0025). One row per News Item:
-- read is final, failed is tried again in a later run while attempts last.
-- content is the Reading, model and prompt_id trace it to what produced it,
-- and read_at is when the last attempt ended.
CREATE TABLE news_readings (
    news_item_id text PRIMARY KEY REFERENCES news_items (id),
    outcome      text NOT NULL CHECK (outcome IN ('read', 'failed')),
    attempts     integer NOT NULL CHECK (attempts > 0),
    model        text NOT NULL,
    prompt_id    text NOT NULL,
    content      jsonb,
    read_at      timestamptz NOT NULL DEFAULT now(),
    CHECK ((outcome = 'read') = (content IS NOT NULL))
);
CREATE INDEX news_readings_read_at_idx ON news_readings (read_at);

-- A Customer's News Digests (ADR 0025), kept as history. Each holds the News
-- Items that became ready in (since, until], grouped by Relevance, with the
-- Editor's reasons, and names the version of the Business Context it read, 0
-- when the Customer had stated none. content is what the dashboard shows.
CREATE TABLE news_digests (
    id                       uuid PRIMARY KEY,
    customer_id              uuid NOT NULL REFERENCES customers (id),
    since                    timestamptz NOT NULL,
    until                    timestamptz NOT NULL,
    business_context_version integer NOT NULL CHECK (business_context_version >= 0),
    named_count              integer NOT NULL CHECK (named_count >= 0),
    finding_count            integer NOT NULL CHECK (finding_count >= 0),
    footprint_count          integer NOT NULL CHECK (footprint_count >= 0),
    peer_count               integer NOT NULL CHECK (peer_count >= 0),
    content                  jsonb NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT now(),
    CHECK (since < until)
);
CREATE INDEX news_digests_customer_idx ON news_digests (customer_id, created_at DESC);

-- +goose Down
DROP TABLE news_digests;
DROP TABLE news_readings;
DROP TABLE news_item_victims;
DROP TABLE news_victims;
DROP TABLE news_items;
