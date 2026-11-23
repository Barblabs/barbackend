-- +goose Up

-- The reasons a User gives to close a Finding by hand (ADR 0035). A match
-- reopens a remediated one, never a false positive, and an accepted risk or a
-- postponed one only after reopen_at.
INSERT INTO finding_close_reasons (id, name) VALUES
    (5, 'remediated'),
    (6, 'false_positive'),
    (7, 'accepted_risk'),
    (8, 'postponed');

-- Who closed a Finding by hand, why and until when; cleared with the rest of
-- the close when it reopens, so only the latest close is kept.
ALTER TABLE findings
    ADD COLUMN closed_by  uuid REFERENCES users (id),
    ADD COLUMN close_note text CHECK (char_length(btrim(close_note)) > 0),
    ADD COLUMN reopen_at  timestamptz,
    ADD CHECK ((closed_by IS NOT NULL) = coalesce(close_reason_id IN (5, 6, 7, 8), false)),
    ADD CHECK ((close_note IS NOT NULL) = coalesce(close_reason_id IN (5, 6, 7, 8), false)),
    ADD CHECK ((reopen_at IS NOT NULL) = coalesce(close_reason_id IN (7, 8), false)),
    ADD CHECK (reopen_at IS NULL OR reopen_at > closed_at);

-- +goose Down
ALTER TABLE findings
    DROP COLUMN reopen_at,
    DROP COLUMN close_note,
    DROP COLUMN closed_by;
DELETE FROM finding_close_reasons WHERE id IN (5, 6, 7, 8);
