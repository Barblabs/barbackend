// Package sources holds the use cases on CMDB Sources: adding one and
// syncing its Assets.
package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

// Service adds CMDB Sources and syncs their Assets.
type Service struct {
	db        *postgres.DB
	providers cmdb.Providers
}

func New(db *postgres.DB, providers cmdb.Providers) *Service {
	return &Service{db: db, providers: providers}
}

func (s *Service) Add(ctx context.Context, customer inventory.CustomerID, provider inventory.CMDBProvider, settings json.RawMessage) (inventory.CMDBSource, error) {
	p, err := s.providers.Lookup(provider)
	if err != nil {
		return inventory.CMDBSource{}, err
	}
	if _, err := p.ParseSettings(settings); err != nil {
		return inventory.CMDBSource{}, fmt.Errorf("settings for %s: %w", provider, err)
	}
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), customer, provider)
	if err != nil {
		return inventory.CMDBSource{}, err
	}
	if err := s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.CreateCMDBSource(ctx, src, settings) }); err != nil {
		return inventory.CMDBSource{}, err
	}
	return src, nil
}

// Sync brings the Assets of a CMDB Source in line with a full snapshot of it.
// Every failure after the source is read is recorded as a failed Sync Run,
// which changed no Asset.
func (s *Service) Sync(ctx context.Context, id inventory.CMDBSourceID) (inventory.SyncRun, error) {
	started := time.Now()
	var src inventory.CMDBSource
	var settings json.RawMessage
	err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		var err error
		src, settings, err = tx.CMDBSource(ctx, id)
		return err
	})
	if err != nil {
		return inventory.SyncRun{}, err
	}
	run, err := s.sync(ctx, src, settings, started)
	if err != nil {
		return inventory.SyncRun{}, s.recordFailure(ctx, id, started, err)
	}
	return run, nil
}

// sync reads the snapshot before locking the source, so a slow CMDB Provider
// never holds the lock. Settings are parsed again because a provider may
// have tightened its rules since the source was added.
func (s *Service) sync(ctx context.Context, src inventory.CMDBSource, settings json.RawMessage, started time.Time) (inventory.SyncRun, error) {
	p, err := s.providers.Lookup(src.Provider())
	if err != nil {
		return inventory.SyncRun{}, err
	}
	parsed, err := p.ParseSettings(settings)
	if err != nil {
		return inventory.SyncRun{}, fmt.Errorf("settings of %s: %w", src.ID(), err)
	}
	snapshot, err := parsed.Snapshot(ctx)
	if err != nil {
		return inventory.SyncRun{}, fmt.Errorf("snapshot of %s: %w", src.ID(), err)
	}
	return s.db.CommitSync(ctx, src.ID(), started, func(existing []*inventory.Asset) (inventory.Reconciliation, error) {
		return inventory.Reconcile(src.ID(), existing, snapshot)
	})
}

// recordFailure records the failed run even when ctx was canceled, since the
// cancellation may be the failure being recorded.
func (s *Service) recordFailure(ctx context.Context, id inventory.CMDBSourceID, started time.Time, cause error) error {
	ctx = context.WithoutCancel(ctx)
	run, err := inventory.FailedRun(id, started, time.Now(), cause)
	if err == nil {
		err = s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.RecordFailedSync(ctx, run) })
	}
	if err != nil {
		err = fmt.Errorf("record failed sync run: %w", err)
	}
	return errors.Join(cause, err)
}
