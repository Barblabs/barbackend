-- +goose Up

CREATE TABLE customers (
    id             uuid PRIMARY KEY,
    name           text NOT NULL UNIQUE,
    created_at     timestamptz NOT NULL DEFAULT now(),
    deactivated_at timestamptz
);

CREATE TABLE user_roles (
    id   smallint PRIMARY KEY,
    name text NOT NULL UNIQUE
);
INSERT INTO user_roles (id, name) VALUES
    (1, 'Platform Admin'),
    (2, 'Customer Admin'),
    (3, 'Viewer');

CREATE TABLE users (
    id          uuid PRIMARY KEY,
    cognito_sub text NOT NULL UNIQUE,
    email       text NOT NULL UNIQUE,
    customer_id uuid REFERENCES customers (id),
    role_id     smallint NOT NULL REFERENCES user_roles (id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

ALTER TABLE cmdb_sources ADD FOREIGN KEY (customer_id) REFERENCES customers (id);
ALTER TABLE asset_owners ADD FOREIGN KEY (customer_id) REFERENCES customers (id);

-- +goose Down
ALTER TABLE asset_owners DROP CONSTRAINT asset_owners_customer_id_fkey;
ALTER TABLE cmdb_sources DROP CONSTRAINT cmdb_sources_customer_id_fkey;
DROP TABLE users;
DROP TABLE user_roles;
DROP TABLE customers;
