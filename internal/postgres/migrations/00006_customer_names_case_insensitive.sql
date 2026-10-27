-- +goose Up
ALTER TABLE customers DROP CONSTRAINT customers_name_key;
CREATE UNIQUE INDEX customers_name_key ON customers (lower(name));

-- +goose Down
DROP INDEX customers_name_key;
ALTER TABLE customers ADD CONSTRAINT customers_name_key UNIQUE (name);
