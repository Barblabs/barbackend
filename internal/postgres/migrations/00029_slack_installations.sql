-- +goose Up

-- One Slack installation per Customer (ADR 0029). The bot token is sealed
-- like CMDB credentials (ADR 0012), so it is bytea. It is nullable because a
-- disconnected installation keeps its row as removed and holds no token.
CREATE TABLE slack_installations (
    customer_id  uuid PRIMARY KEY REFERENCES customers (id),
    team_id      text NOT NULL,
    team_name    text NOT NULL,
    bot_token    bytea,
    channel_id   text NOT NULL DEFAULT '',
    channel_name text NOT NULL DEFAULT '',
    state        text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'needs re-authorisation', 'removed')),
    installed_at timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    removed_at   timestamptz
);

-- +goose Down
DROP TABLE slack_installations;
