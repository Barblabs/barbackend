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
	"github.com/jackc/pgx/v5/pgconn"
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
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == connectedCustomerIndex {
		return fmt.Errorf("insert cmdb source %s: %w", src.ID(), ErrAlreadyConnected)
	}
	if err != nil {
		return fmt.Errorf("insert cmdb source %s: %w", src.ID(), err)
	}
	return nil
}

// connectedCustomerIndex keeps a Customer to at most one Connected CMDB Source.
const connectedCustomerIndex = "cmdb_sources_connected_customer_idx"

func (t *Tx) CMDBSource(ctx context.Context, id inventory.CMDBSourceID) (StoredCMDBSource, error) {
	row, err := t.q.GetCMDBSource(ctx, uuid.UUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCMDBSource{}, fmt.Errorf("cmdb source %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return StoredCMDBSource{}, fmt.Errorf("get cmdb source %s: %w", id, err)
	}
	return restoreCMDBSource(sqlcgen.GetConnectedCMDBSourceRow(row))
}

// ConnectedCMDBSource fails with ErrNotFound when the Customer has no
// Connected CMDB Source.
func (t *Tx) ConnectedCMDBSource(ctx context.Context, customer inventory.CustomerID) (StoredCMDBSource, error) {
	row, err := t.q.GetConnectedCMDBSource(ctx, uuid.UUID(customer))
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCMDBSource{}, fmt.Errorf("connected cmdb source of customer %s: %w", customer, ErrNotFound)
	}
	if err != nil {
		return StoredCMDBSource{}, fmt.Errorf("get connected cmdb source of customer %s: %w", customer, err)
	}
	return restoreCMDBSource(row)
}

func restoreCMDBSource(row sqlcgen.GetConnectedCMDBSourceRow) (StoredCMDBSource, error) {
	src, err := inventory.NewCMDBSource(
		inventory.CMDBSourceID(row.ID),
		inventory.CustomerID(row.CustomerID),
		inventory.CMDBProvider(row.Provider),
	)
	if err != nil {
		return StoredCMDBSource{}, fmt.Errorf("restore cmdb source %s: %w", row.ID, err)
	}
	return StoredCMDBSource{Source: src, Settings: row.Settings, Credentials: row.Credentials}, nil
}
