package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"github.com/google/uuid"
)

func TestCMDBSourceRoundTrip(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	ctx := context.Background()
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), newCustomer(), "itop")
	if err != nil {
		t.Fatal(err)
	}
	// Written in jsonb's canonical form, so it reads back byte for byte.
	settings := json.RawMessage(`{"url": "http://localhost:8000"}`)
	credentials := []byte{0, 1, 0xff}

	inTx(t, db, func(tx *postgres.Tx) error { return tx.CreateCMDBSource(ctx, src, settings, credentials) })

	inTx(t, db, func(tx *postgres.Tx) error {
		got, err := tx.CMDBSource(ctx, src.ID())
		if err != nil {
			return err
		}
		if got.Source != src {
			t.Errorf("source = %+v, want %+v", got.Source, src)
		}
		if string(got.Settings) != string(settings) {
			t.Errorf("settings = %s, want %s", got.Settings, settings)
		}
		if !bytes.Equal(got.Credentials, credentials) {
			t.Errorf("credentials = %x, want %x", got.Credentials, credentials)
		}
		return nil
	})
}

func TestCMDBSourceNotFound(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.CMDBSource(context.Background(), inventory.CMDBSourceID(uuid.New()))
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSecondConnectedCMDBSourceIsRefused(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	customer := newCustomer()
	newSource(t, db, customer)
	second, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), customer, "itop")
	if err != nil {
		t.Fatal(err)
	}

	err = db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.CreateCMDBSource(context.Background(), second, []byte(`{}`), []byte{})
	})

	if !errors.Is(err, postgres.ErrAlreadyConnected) {
		t.Errorf("err = %v, want ErrAlreadyConnected", err)
	}
}
