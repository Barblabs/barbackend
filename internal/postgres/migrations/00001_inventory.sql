-- +goose Up

-- Catalog ids equal the Go constants in internal/inventory (ADR 0006).
CREATE TABLE asset_kinds (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO asset_kinds (id, name) VALUES
    (1, 'Server'),
    (2, 'Virtual Machine'),
    (3, 'Workstation'),
    (4, 'Network Device');

CREATE TABLE criticalities (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO criticalities (id, name) VALUES
    (1, 'High'),
    (2, 'Medium'),
    (3, 'Low');

CREATE TABLE exposures (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO exposures (id, name) VALUES
    (1, 'Internet-facing'),
    (2, 'Internal');

CREATE TABLE software_roles (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO software_roles (id, name) VALUES
    (1, 'Operating System'),
    (2, 'Application');

-- customer_id has no foreign key until the customers table exists.
CREATE TABLE cmdb_sources (
    id          uuid PRIMARY KEY,
    customer_id uuid NOT NULL,
    provider    text NOT NULL,
    settings    jsonb NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE asset_owners (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id uuid NOT NULL,
    email       text NOT NULL,
    UNIQUE (customer_id, email)
);

CREATE TABLE assets (
    cmdb_source_id       uuid NOT NULL REFERENCES cmdb_sources (id),
    record_id            text NOT NULL,
    name                 text NOT NULL,
    description          text NOT NULL,
    kind_id              smallint NOT NULL REFERENCES asset_kinds (id),
    hardware_vendor      text,
    hardware_model       text,
    criticality_id       smallint REFERENCES criticalities (id),
    imported_owner_id    bigint REFERENCES asset_owners (id),
    retired              boolean NOT NULL,
    declared_owner_id    bigint REFERENCES asset_owners (id),
    declared_exposure_id smallint REFERENCES exposures (id),
    created_at           timestamptz NOT NULL DEFAULT now(),
    imported_changed_at  timestamptz NOT NULL DEFAULT now(),
    inactive_since       timestamptz,
    PRIMARY KEY (cmdb_source_id, record_id),
    CHECK ((hardware_vendor IS NULL) = (hardware_model IS NULL))
);

-- position keeps components in the order the CMDB Source listed them.
CREATE TABLE software_components (
    cmdb_source_id uuid NOT NULL,
    record_id      text NOT NULL,
    position       smallint NOT NULL,
    role_id        smallint NOT NULL REFERENCES software_roles (id),
    name           text NOT NULL,
    version        text NOT NULL,
    product_vendor text,
    product_name   text,
    PRIMARY KEY (cmdb_source_id, record_id, position),
    FOREIGN KEY (cmdb_source_id, record_id) REFERENCES assets (cmdb_source_id, record_id) ON DELETE CASCADE,
    CHECK ((product_vendor IS NULL) = (product_name IS NULL))
);

-- +goose Down
DROP TABLE software_components;
DROP TABLE assets;
DROP TABLE asset_owners;
DROP TABLE cmdb_sources;
DROP TABLE software_roles;
DROP TABLE exposures;
DROP TABLE criticalities;
DROP TABLE asset_kinds;
