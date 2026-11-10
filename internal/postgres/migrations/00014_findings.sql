-- +goose Up

-- One Finding per Asset, Product and Vulnerability (ADR 0020): opened, closed
-- and reopened, never deleted. The Product is stored in lower case, as
-- Products match ignoring case (ADR 0015). component_name and
-- component_version are copied from the matched Software Component, which has
-- no identity of its own. evidence is the matched nvd/1 affected entry.
-- A Finding is open while closed_at is null.
CREATE TABLE findings (
    id                uuid PRIMARY KEY,
    cmdb_source_id    uuid NOT NULL,
    record_id         text NOT NULL,
    product_vendor    text NOT NULL CHECK (product_vendor <> '' AND product_vendor = lower(btrim(product_vendor))),
    product_name      text NOT NULL CHECK (product_name <> '' AND product_name = lower(btrim(product_name))),
    cve_id            text NOT NULL REFERENCES vulnerabilities (cve_id),
    component_name    text NOT NULL,
    component_version text NOT NULL,
    evidence          jsonb NOT NULL,
    first_opened_at   timestamptz NOT NULL,
    opened_at         timestamptz NOT NULL,
    closed_at         timestamptz,
    close_reason_id   smallint REFERENCES finding_close_reasons (id),
    FOREIGN KEY (cmdb_source_id, record_id) REFERENCES assets (cmdb_source_id, record_id),
    UNIQUE (cmdb_source_id, record_id, product_vendor, product_name, cve_id),
    CHECK ((closed_at IS NULL) = (close_reason_id IS NULL)),
    CHECK (first_opened_at <= opened_at),
    CHECK (closed_at IS NULL OR closed_at >= opened_at)
);
-- KEV and EPSS rescore the open Findings of one CVE.
CREATE INDEX findings_open_cve_idx ON findings (cve_id) WHERE closed_at IS NULL;

-- +goose Down
DROP TABLE findings;
