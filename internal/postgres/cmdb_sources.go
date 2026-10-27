package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
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

// UpdateConnectedLogin replaces the settings and sealed credentials of a
// Connected CMDB Source, keeping its id and so its Assets. It fails with
// ErrNotConnected when the source is not connected.
func (t *Tx) UpdateConnectedLogin(ctx context.Context, id inventory.CMDBSourceID, settings json.RawMessage, credentials []byte) error {
	n, err := t.q.UpdateConnectedCMDBSourceLogin(ctx, sqlcgen.UpdateConnectedCMDBSourceLoginParams{
		ID:          uuid.UUID(id),
		Settings:    settings,
		Credentials: credentials,
	})
	if err != nil {
		return fmt.Errorf("update login of cmdb source %s: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("cmdb source %s: %w", id, ErrNotConnected)
	}
	return nil
}

// DisconnectCMDBSource makes the Customer's Connected CMDB Source a
// Disconnected one and its Assets Inactive, deleting nothing. It locks the
// source as CommitSync does, so it fails at once with ErrSyncInProgress
// while a Sync commits, and with ErrNotConnected when nothing is connected.
func (t *Tx) DisconnectCMDBSource(ctx context.Context, customer tenancy.CustomerID) error {
	id, err := t.q.LockConnectedCMDBSource(ctx, uuid.UUID(customer))
	if err != nil {
		return lockError(fmt.Sprintf("customer %s", customer), ErrNotConnected, err)
	}
	if err := t.q.DisconnectCMDBSource(ctx, id); err != nil {
		return fmt.Errorf("disconnect cmdb source %s: %w", id, err)
	}
	if err := t.q.DeactivateSourceAssets(ctx, id); err != nil {
		return fmt.Errorf("deactivate assets of %s: %w", id, err)
	}
	return nil
}

const connectedCustomerIndex = "cmdb_sources_connected_customer_idx"

// ConnectedCMDBSource fails with ErrNotConnected when the Customer has no
// Connected CMDB Source.
func (t *Tx) ConnectedCMDBSource(ctx context.Context, customer tenancy.CustomerID) (StoredCMDBSource, error) {
	row, err := t.q.GetConnectedCMDBSource(ctx, uuid.UUID(customer))
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredCMDBSource{}, fmt.Errorf("customer %s: %w", customer, ErrNotConnected)
	}
	if err != nil {
		return StoredCMDBSource{}, fmt.Errorf("get connected cmdb source of customer %s: %w", customer, err)
	}
	src, err := inventory.NewCMDBSource(
		inventory.CMDBSourceID(row.ID),
		tenancy.CustomerID(row.CustomerID),
		inventory.CMDBProvider(row.Provider),
	)
	if err != nil {
		return StoredCMDBSource{}, fmt.Errorf("restore cmdb source %s: %w", row.ID, err)
	}
	return StoredCMDBSource{Source: src, Settings: row.Settings, Credentials: row.Credentials}, nil
}
