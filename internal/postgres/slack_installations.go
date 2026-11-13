package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// StoredSlackInstallation is a Customer's Slack installation as the database
// holds it: the bot token is still sealed (ADR 0012) and the state is the
// plain text ADR 0029 gives it.
type StoredSlackInstallation struct {
	Customer    tenancy.CustomerID
	TeamID      string
	TeamName    string
	BotToken    []byte
	ChannelID   string
	ChannelName string
	State       string
	InstalledAt time.Time
	UpdatedAt   time.Time
	RemovedAt   *time.Time
}

// SlackInstallation fails with ErrNotFound when the Customer has none.
func (t *Tx) SlackInstallation(ctx context.Context, customer tenancy.CustomerID) (StoredSlackInstallation, error) {
	row, err := t.q.GetSlackInstallation(ctx, uuid.UUID(customer))
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredSlackInstallation{}, fmt.Errorf("slack installation of customer %s: %w", customer, ErrNotFound)
	}
	if err != nil {
		return StoredSlackInstallation{}, fmt.Errorf("get slack installation of customer %s: %w", customer, err)
	}
	stored := StoredSlackInstallation{
		Customer:    tenancy.CustomerID(row.CustomerID),
		TeamID:      row.TeamID,
		TeamName:    row.TeamName,
		BotToken:    row.BotToken,
		ChannelID:   row.ChannelID,
		ChannelName: row.ChannelName,
		State:       row.State,
		InstalledAt: row.InstalledAt,
		UpdatedAt:   row.UpdatedAt,
		RemovedAt:   row.RemovedAt,
	}
	return stored, nil
}

// SaveSlackInstallation stores a fresh token and workspace, returning a
// removed installation to active and keeping the Security Team channel an
// admin already picked.
func (t *Tx) SaveSlackInstallation(ctx context.Context, customer tenancy.CustomerID, teamID, teamName string, botToken []byte) error {
	err := t.q.UpsertSlackInstallation(ctx, sqlcgen.UpsertSlackInstallationParams{
		CustomerID: uuid.UUID(customer),
		TeamID:     teamID,
		TeamName:   teamName,
		BotToken:   botToken,
	})
	if err != nil {
		return fmt.Errorf("save slack installation of customer %s: %w", customer, err)
	}
	return nil
}

// SetSlackChannel stores the Security Team channel. It fails with
// ErrNotFound when the Customer has no installation or it is removed.
func (t *Tx) SetSlackChannel(ctx context.Context, customer tenancy.CustomerID, channelID, channelName string) error {
	n, err := t.q.SetSlackInstallationChannel(ctx, sqlcgen.SetSlackInstallationChannelParams{
		CustomerID:  uuid.UUID(customer),
		ChannelID:   channelID,
		ChannelName: channelName,
	})
	if err != nil {
		return fmt.Errorf("set slack channel of customer %s: %w", customer, err)
	}
	if n == 0 {
		return fmt.Errorf("slack installation of customer %s: %w", customer, ErrNotFound)
	}
	return nil
}

// SetSlackState changes the installation's state, such as to
// needs re-authorisation after Slack revoked the token (ADR 0029).
func (t *Tx) SetSlackState(ctx context.Context, customer tenancy.CustomerID, state string) error {
	n, err := t.q.SetSlackInstallationState(ctx, sqlcgen.SetSlackInstallationStateParams{
		CustomerID: uuid.UUID(customer),
		State:      state,
	})
	if err != nil {
		return fmt.Errorf("set slack state of customer %s: %w", customer, err)
	}
	if n == 0 {
		return fmt.Errorf("slack installation of customer %s: %w", customer, ErrNotFound)
	}
	return nil
}

// RemoveSlackInstallation marks the Customer's installation removed and
// drops its sealed token, keeping the row so a later reinstall can restore
// it. It is idempotent.
func (t *Tx) RemoveSlackInstallation(ctx context.Context, customer tenancy.CustomerID) error {
	if _, err := t.q.RemoveSlackInstallation(ctx, uuid.UUID(customer)); err != nil {
		return fmt.Errorf("remove slack installation of customer %s: %w", customer, err)
	}
	return nil
}
