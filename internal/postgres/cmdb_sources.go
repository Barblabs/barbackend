package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// StoredCMDBSource is a CMDB Source with what only its adapter can read: its
// settings and its sealed credentials.
type StoredCMDBSource struct {
	Source      inventory.CMDBSource
	Settings    json.RawMessage
	Credentials []byte
}

// Settings and credentials are stored as given: only the CMDB Provider's
// adapter can validate them, and the credentials arrive sealed.
func (t *Tx) CreateCMDBSource(ctx context.Context, src inventory.CMDBSource, settings json.RawMessage, credentials []byte) error {
	err := t.q.InsertCMDBSource(ctx, sqlcgen.InsertCMDBSourceParams{
		ID:          uuid.UUID(src.ID()),
		CustomerID:  uuid.UUID(src.Customer()),
		Provider:    string(src.Provider()),
		Settings:    settings,
		Credentials: credentials,
	})
	if err != nil {
		return fmt.Errorf("insert cmdb source %s: %w", src.ID(), err)
	}
	return nil
}

func (t *Tx) CMDBSource(ctx context.Context, id inventory.CMDBSourceID) (StoredCMDBSource, error) {
	row, err := t.q.GetCMDBSource(ctx, uuid.UUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCMDBSource{}, fmt.Errorf("cmdb source %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return StoredCMDBSource{}, fmt.Errorf("get cmdb source %s: %w", id, err)
	}
	src, err := inventory.NewCMDBSource(
		inventory.CMDBSourceID(row.ID),
		inventory.CustomerID(row.CustomerID),
		inventory.CMDBProvider(row.Provider),
	)
	if err != nil {
		return StoredCMDBSource{}, fmt.Errorf("restore cmdb source %s: %w", id, err)
	}
	return StoredCMDBSource{Source: src, Settings: row.Settings, Credentials: row.Credentials}, nil
}
