package postgres_test

import (
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

	inTx(t, db, func(tx *postgres.Tx) error { return tx.CreateCMDBSource(ctx, src, settings) })

	inTx(t, db, func(tx *postgres.Tx) error {
		got, gotSettings, err := tx.CMDBSource(ctx, src.ID())
		if err != nil {
			return err
		}
		if got != src {
			t.Errorf("source = %+v, want %+v", got, src)
		}
		if string(gotSettings) != string(settings) {
			t.Errorf("settings = %s, want %s", gotSettings, settings)
		}
		return nil
	})
}

func TestCMDBSourceNotFound(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, _, err := tx.CMDBSource(context.Background(), inventory.CMDBSourceID(uuid.New()))
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
