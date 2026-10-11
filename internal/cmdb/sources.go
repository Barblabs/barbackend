package cmdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

var ErrUnknownProvider = errors.New("unknown cmdb provider")

// Sources adds CMDB Sources and syncs their Assets.
type Sources struct {
	db        *postgres.DB
	providers Providers
}

func NewSources(db *postgres.DB, providers Providers) *Sources {
	return &Sources{db: db, providers: providers}
}

func (s *Sources) Add(ctx context.Context, customer inventory.CustomerID, provider inventory.CMDBProvider, settings json.RawMessage) (inventory.CMDBSource, error) {
	p, err := s.provider(provider)
	if err != nil {
		return inventory.CMDBSource{}, err
	}
	if err := p.ValidateSettings(settings); err != nil {
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
func (s *Sources) Sync(ctx context.Context, id inventory.CMDBSourceID) (inventory.SyncRun, error) {
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
// never holds the lock. Settings are validated again because a provider may
// have tightened its rules since the source was added.
func (s *Sources) sync(ctx context.Context, src inventory.CMDBSource, settings json.RawMessage, started time.Time) (inventory.SyncRun, error) {
	p, err := s.provider(src.Provider())
	if err != nil {
		return inventory.SyncRun{}, err
	}
	if err := p.ValidateSettings(settings); err != nil {
		return inventory.SyncRun{}, fmt.Errorf("settings of %s: %w", src.ID(), err)
	}
	snapshot, err := p.Snapshot(ctx, settings)
	if err != nil {
		return inventory.SyncRun{}, fmt.Errorf("snapshot of %s: %w", src.ID(), err)
	}
	var run inventory.SyncRun
	err = s.db.InLockedSource(ctx, src.ID(), started, func(tx *postgres.SourceTx) error {
		existing, err := tx.Assets(ctx)
		if err != nil {
			return err
		}
		r, err := inventory.Reconcile(src.ID(), existing, snapshot)
		if err != nil {
			return err
		}
		if err := tx.Save(ctx, r); err != nil {
			return err
		}
		run, err = inventory.SucceededRun(r, started, time.Now())
		if err != nil {
			return err
		}
		return tx.RecordSyncRun(ctx, run)
	})
	return run, err
}

// recordFailure records the failed run even when ctx was canceled, since the
// cancellation may be the failure being recorded.
func (s *Sources) recordFailure(ctx context.Context, id inventory.CMDBSourceID, started time.Time, cause error) error {
	ctx = context.WithoutCancel(ctx)
	run, err := inventory.FailedRun(id, started, time.Now(), cause)
	if err == nil {
		err = s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.RecordSyncRun(ctx, run) })
	}
	if err != nil {
		err = fmt.Errorf("record failed sync run: %w", err)
	}
	return errors.Join(cause, err)
}

func (s *Sources) provider(name inventory.CMDBProvider) (Provider, error) {
	p, ok := s.providers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}
	return p, nil
}
