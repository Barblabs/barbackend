-- name: GetSlackInstallation :one
SELECT customer_id, team_id, team_name, bot_token, channel_id, channel_name, state, installed_at, updated_at, removed_at
FROM slack_installations
WHERE customer_id = @customer_id;

-- name: UpsertSlackInstallation :exec
INSERT INTO slack_installations (customer_id, team_id, team_name, bot_token, state, installed_at, updated_at)
VALUES (@customer_id, @team_id, @team_name, @bot_token, 'active', now(), now())
ON CONFLICT (customer_id) DO UPDATE SET
    team_id = EXCLUDED.team_id,
    team_name = EXCLUDED.team_name,
    bot_token = EXCLUDED.bot_token,
    state = 'active',
    updated_at = now(),
    removed_at = NULL;

-- name: SetSlackInstallationChannel :execrows
UPDATE slack_installations
SET channel_id = @channel_id,
    channel_name = @channel_name,
    updated_at = now()
WHERE customer_id = @customer_id AND state <> 'removed';

-- name: SetSlackInstallationState :execrows
UPDATE slack_installations
SET state = @state,
    updated_at = now()
WHERE customer_id = @customer_id;

-- name: RemoveSlackInstallation :execrows
UPDATE slack_installations
SET state = 'removed',
    bot_token = NULL,
    updated_at = now(),
    removed_at = now()
WHERE customer_id = @customer_id AND state <> 'removed';
