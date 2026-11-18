-- +goose Up

ALTER TABLE users ALTER COLUMN cognito_sub DROP NOT NULL;

CREATE TABLE user_invitations (
    user_id         uuid PRIMARY KEY REFERENCES users (id),
    attempts        integer NOT NULL,
    next_attempt_at timestamptz NOT NULL,
    last_error      text
);

-- +goose Down
DROP TABLE user_invitations;
ALTER TABLE users ALTER COLUMN cognito_sub SET NOT NULL;
