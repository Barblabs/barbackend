-- +goose Up

-- An Area is keyed by its Source Reference, like an Asset, so a rename in the
-- CMDB Source keeps the row and the owner_email a Customer Admin stated. A
-- Sync never writes owner_email.
CREATE TABLE customer_areas (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cmdb_source_id      uuid NOT NULL REFERENCES cmdb_sources (id),
    record_id           text NOT NULL,
    name                text NOT NULL,
    owner_email         text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    imported_changed_at timestamptz NOT NULL DEFAULT now(),
    inactive_since      timestamptz,
    UNIQUE (cmdb_source_id, record_id)
);

-- Referencing the Area by Source Reference lets Postgres guarantee that an
-- Asset's Area belongs to the Asset's own CMDB Source.
ALTER TABLE assets
    ADD COLUMN area_record_id text,
    ADD FOREIGN KEY (cmdb_source_id, area_record_id)
        REFERENCES customer_areas (cmdb_source_id, record_id);

-- +goose Down
ALTER TABLE assets DROP COLUMN area_record_id;
DROP TABLE customer_areas;
