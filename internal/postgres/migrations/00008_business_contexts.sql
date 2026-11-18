-- +goose Up

-- Each save of a Customer's Business Context is a new version and none is ever
-- updated, so whatever an Agent derives from one can name the version it read.
-- content is the Business Context in the shape that schema names.
CREATE TABLE business_contexts (
    customer_id uuid NOT NULL REFERENCES customers (id),
    version     integer NOT NULL,
    schema      text NOT NULL,
    content     jsonb NOT NULL,
    saved_by    uuid NOT NULL REFERENCES users (id),
    saved_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (customer_id, version)
);

-- +goose Down
DROP TABLE business_contexts;
