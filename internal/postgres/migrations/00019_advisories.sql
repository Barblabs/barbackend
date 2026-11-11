-- +goose Up

-- The Advisories that name at least one stored Vulnerability (ADR 0022), one
-- row per STIX report shared by every Customer: they are public. object is the
-- STIX report as its Feed emitted it; a bulletin published again replaces it.
CREATE TABLE advisories (
    id           text PRIMARY KEY CHECK (id ~ '^report--[0-9a-f-]{36}$'),
    feed         text NOT NULL CHECK (length(feed) > 0),
    published_at timestamptz NOT NULL,
    object       jsonb NOT NULL,
    modified_at  timestamptz NOT NULL,
    stored_at    timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE advisories;
