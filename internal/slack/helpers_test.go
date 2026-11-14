package slack_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/url"
	"testing"

	"barbackend/internal/encryption"
	"barbackend/internal/postgres"
	"barbackend/internal/slack"
	"barbackend/internal/slack/slacktest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func testKey(t *testing.T) encryption.Key {
	t.Helper()
	key, err := encryption.ParseKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newCustomer(t *testing.T, db *postgres.DB) tenancy.CustomerID {
	t.Helper()
	c, err := tenancy.NewCustomer(tenancy.CustomerID(uuid.New()), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.CreateCustomer(context.Background(), c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return c.ID()
}

func adminOf(customer tenancy.CustomerID) tenancy.User {
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "admin@example.com", tenancy.CustomerAdmin, customer)
	if err != nil {
		panic(err)
	}
	return u
}

func install(t *testing.T, svc *slack.Service, caller tenancy.User) {
	t.Helper()
	authorize, err := svc.StartInstall(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.HandleCallback(context.Background(), slacktest.Code, stateOf(t, authorize)); err != nil {
		t.Fatal(err)
	}
}

func storedInstallation(t *testing.T, db *postgres.DB, customer tenancy.CustomerID) postgres.StoredSlackInstallation {
	t.Helper()
	stored, err := postgres.InTxValue(context.Background(), db, func(tx *postgres.Tx) (postgres.StoredSlackInstallation, error) {
		return tx.SlackInstallation(context.Background(), customer)
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func stateOf(t *testing.T, authorize string) string {
	t.Helper()
	u, err := url.Parse(authorize)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("authorize URL %q carries no state", authorize)
	}
	return state
}
