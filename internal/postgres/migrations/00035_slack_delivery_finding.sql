-- +goose Up

-- The Finding an Alert is about (ADR 0033). A batch of the Initial Load is
-- about several, and other kinds of message about none, so it is nullable.
ALTER TABLE slack_deliveries
    ADD COLUMN finding_id uuid REFERENCES findings (id);

-- +goose Down
ALTER TABLE slack_deliveries
    DROP COLUMN finding_id;
