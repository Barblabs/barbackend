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

// Settings are stored as given: only the CMDB Provider's adapter can validate them.
func (t *Tx) CreateCMDBSource(ctx context.Context, src inventory.CMDBSource, settings json.RawMessage) error {
	err := t.q.InsertCMDBSource(ctx, sqlcgen.InsertCMDBSourceParams{
		ID:         uuid.UUID(src.ID()),
		CustomerID: uuid.UUID(src.Customer()),
		Provider:   string(src.Provider()),
		Settings:   settings,
	})
	if err != nil {
		return fmt.Errorf("insert cmdb source %s: %w", src.ID(), err)
	}
	return nil
}

func (t *Tx) CMDBSource(ctx context.Context, id inventory.CMDBSourceID) (inventory.CMDBSource, json.RawMessage, error) {
	row, err := t.q.GetCMDBSource(ctx, uuid.UUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return inventory.CMDBSource{}, nil, fmt.Errorf("cmdb source %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return inventory.CMDBSource{}, nil, fmt.Errorf("get cmdb source %s: %w", id, err)
	}
	src, err := inventory.NewCMDBSource(
		inventory.CMDBSourceID(row.ID),
		inventory.CustomerID(row.CustomerID),
		inventory.CMDBProvider(row.Provider),
	)
	if err != nil {
		return inventory.CMDBSource{}, nil, fmt.Errorf("restore cmdb source %s: %w", id, err)
	}
	return src, row.Settings, nil
}
