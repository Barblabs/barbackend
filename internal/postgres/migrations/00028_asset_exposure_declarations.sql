-- +goose Up

-- The handle the HTTP API uses for an Asset, as customer_areas.id is for an
-- Area; the Source Reference stays the key (ADR 0021).
ALTER TABLE assets ADD COLUMN id bigint NOT NULL GENERATED ALWAYS AS IDENTITY UNIQUE;

-- Nothing wrote declared_exposure_id before this migration, so every row
-- already meets the CHECK.
ALTER TABLE assets
    ADD COLUMN exposure_declared_by uuid REFERENCES users (id),
    ADD COLUMN exposure_declared_at timestamptz,
    ADD CHECK ((declared_exposure_id IS NULL) = (exposure_declared_by IS NULL)
               AND (declared_exposure_id IS NULL) = (exposure_declared_at IS NULL));

-- +goose Down
ALTER TABLE assets
    DROP COLUMN exposure_declared_at,
    DROP COLUMN exposure_declared_by,
    DROP COLUMN id;
