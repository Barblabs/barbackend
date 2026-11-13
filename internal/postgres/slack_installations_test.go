package postgres_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
)

func slackInstallation(t *testing.T, db *postgres.DB, customer tenancy.CustomerID) postgres.StoredSlackInstallation {
	t.Helper()
	stored, err := postgres.InTxValue(context.Background(), db, func(tx *postgres.Tx) (postgres.StoredSlackInstallation, error) {
		return tx.SlackInstallation(context.Background(), customer)
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func saveSlack(t *testing.T, db *postgres.DB, customer tenancy.CustomerID, teamID, teamName, token string) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.SaveSlackInstallation(context.Background(), customer, teamID, teamName, []byte(token))
	})
}

func TestSlackInstallationRoundTrip(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	customer := newCustomer(t, db)

	saveSlack(t, db, customer, "T1", "Acme", "sealed-token")

	got := slackInstallation(t, db, customer)
	if got.Customer != customer || got.TeamID != "T1" || got.TeamName != "Acme" || string(got.BotToken) != "sealed-token" {
		t.Errorf("installation = %+v, want T1 Acme with the token", got)
	}
	if got.State != "active" || got.ChannelID != "" || got.ChannelName != "" || got.RemovedAt != nil {
		t.Errorf("installation = %+v, want active without a channel or removal", got)
	}
	if got.InstalledAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("timestamps are zero")
	}
}

func TestSlackInstallationNotFound(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	customer := newCustomer(t, db)

	_, err := postgres.InTxValue(context.Background(), db, func(tx *postgres.Tx) (postgres.StoredSlackInstallation, error) {
		return tx.SlackInstallation(context.Background(), customer)
	})

	if !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestSetSlackChannel(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	customer := newCustomer(t, db)
	saveSlack(t, db, customer, "T1", "Acme", "sealed-token")

	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.SetSlackChannel(context.Background(), customer, "C1", "security")
	})

	got := slackInstallation(t, db, customer)
	if got.ChannelID != "C1" || got.ChannelName != "security" {
		t.Errorf("channel = %q %q, want C1 security", got.ChannelID, got.ChannelName)
	}

	missing := newCustomer(t, db)
	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.SetSlackChannel(context.Background(), missing, "C1", "security")
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestSaveSlackInstallationKeepsTheChannel(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	customer := newCustomer(t, db)
	saveSlack(t, db, customer, "T1", "Acme", "first-token")
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.SetSlackChannel(context.Background(), customer, "C1", "security")
	})
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.SetSlackState(context.Background(), customer, "needs re-authorisation")
	})

	saveSlack(t, db, customer, "T2", "Acme Renamed", "second-token")

	got := slackInstallation(t, db, customer)
	if got.TeamID != "T2" || got.TeamName != "Acme Renamed" || string(got.BotToken) != "second-token" {
		t.Errorf("installation = %+v, want the new workspace and token", got)
	}
	if got.State != "active" || got.ChannelID != "C1" {
		t.Errorf("installation = %+v, want active with the channel kept", got)
	}
}

func TestSetSlackState(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	customer := newCustomer(t, db)
	saveSlack(t, db, customer, "T1", "Acme", "sealed-token")

	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.SetSlackState(context.Background(), customer, "needs re-authorisation")
	})

	if got := slackInstallation(t, db, customer).State; got != "needs re-authorisation" {
		t.Errorf("state = %q, want needs re-authorisation", got)
	}

	missing := newCustomer(t, db)
	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.SetSlackState(context.Background(), missing, "active")
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRemoveSlackInstallation(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	customer := newCustomer(t, db)
	saveSlack(t, db, customer, "T1", "Acme", "sealed-token")
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.SetSlackChannel(context.Background(), customer, "C1", "security")
	})

	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.RemoveSlackInstallation(context.Background(), customer)
	})

	got := slackInstallation(t, db, customer)
	if got.State != "removed" || got.BotToken != nil || got.RemovedAt == nil {
		t.Errorf("installation = %+v, want removed with no token", got)
	}

	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.RemoveSlackInstallation(context.Background(), customer)
	})
	if got := slackInstallation(t, db, customer); got.State != "removed" {
		t.Errorf("second remove state = %q, want removed", got.State)
	}

	saveSlack(t, db, customer, "T1", "Acme", "new-token")

	got = slackInstallation(t, db, customer)
	if got.State != "active" || string(got.BotToken) != "new-token" || got.RemovedAt != nil || got.ChannelID != "C1" {
		t.Errorf("installation after reinstall = %+v, want active with the channel kept", got)
	}
}
