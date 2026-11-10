-- +goose Up

-- Only the Vulnerabilities that opened at least one Finding are stored
-- (ADR 0015, ADR 0019), one row per CVE shared by every Customer. object is
-- the STIX vulnerability with its nvd/1, epss/1 and kev/1 extensions; each
-- Feed updates only its own extension key (ADR 0010).
CREATE TABLE vulnerabilities (
    cve_id      text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    object      jsonb NOT NULL,
    modified_at timestamptz NOT NULL,
    stored_at   timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE vulnerabilities;
