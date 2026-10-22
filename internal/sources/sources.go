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
	"barbackend/internal/encryption"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

// ErrNoCredentials is a CMDB Source added before credentials were stored
// (ADR 0012): its secrets were never in the database, so it must be added again.
var ErrNoCredentials = errors.New("cmdb source has no stored credentials, add it again")

// Service adds CMDB Sources and syncs their Assets. It seals their
// credentials with key, so adapters only ever see them decrypted (ADR 0012).
type Service struct {
	db        *postgres.DB
	providers cmdb.Providers
	key       encryption.Key
}

func New(db *postgres.DB, providers cmdb.Providers, key encryption.Key) *Service {
	return &Service{db: db, providers: providers, key: key}
}

// Add stores a CMDB Source with plain settings and sealed credentials, after
// its CMDB Provider has validated both.
func (s *Service) Add(ctx context.Context, customer inventory.CustomerID, provider inventory.CMDBProvider, settings, credentials json.RawMessage) (inventory.CMDBSource, error) {
	p, err := s.providers.Lookup(provider)
	if err != nil {
		return inventory.CMDBSource{}, err
	}
	if _, err := p.ParseSettings(settings, credentials); err != nil {
		return inventory.CMDBSource{}, fmt.Errorf("parse %s source: %w", provider, err)
	}
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), customer, provider)
	if err != nil {
		return inventory.CMDBSource{}, err
	}
	sealed, err := s.key.Seal(credentials, owner(src.ID()))
	if err != nil {
		return inventory.CMDBSource{}, fmt.Errorf("seal credentials: %w", err)
	}
	if err := s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.CreateCMDBSource(ctx, src, settings, sealed) }); err != nil {
		return inventory.CMDBSource{}, err
	}
	return src, nil
}

// owner binds credentials to their CMDB Source, so sealed credentials copied
// to another source fail to open.
func owner(id inventory.CMDBSourceID) []byte {
	return []byte(id.String())
}

// Sync brings the Assets of a CMDB Source in line with a full snapshot of it.
// Every failure after the source is read is recorded as a failed Sync Run,
// which changed no Asset.
func (s *Service) Sync(ctx context.Context, id inventory.CMDBSourceID) (inventory.SyncRun, error) {
	started := time.Now()
	var stored postgres.StoredCMDBSource
	err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		var err error
		stored, err = tx.CMDBSource(ctx, id)
		return err
	})
	if err != nil {
		return inventory.SyncRun{}, err
	}
	run, err := s.sync(ctx, stored, started)
	if err != nil {
		return inventory.SyncRun{}, s.recordFailure(ctx, id, started, err)
	}
	return run, nil
}

// sync reads the snapshot before locking the source, so a slow CMDB Provider
// never holds the lock. Settings are parsed again because a provider may
// have tightened its rules since the source was added.
func (s *Service) sync(ctx context.Context, stored postgres.StoredCMDBSource, started time.Time) (inventory.SyncRun, error) {
	src := stored.Source
	p, err := s.providers.Lookup(src.Provider())
	if err != nil {
		return inventory.SyncRun{}, err
	}
	if len(stored.Credentials) == 0 {
		return inventory.SyncRun{}, fmt.Errorf("%w: %s", ErrNoCredentials, src.ID())
	}
	credentials, err := s.key.Open(stored.Credentials, owner(src.ID()))
	if err != nil {
		return inventory.SyncRun{}, fmt.Errorf("credentials of %s: %w", src.ID(), err)
	}
	parsed, err := p.ParseSettings(stored.Settings, credentials)
	if err != nil {
		return inventory.SyncRun{}, fmt.Errorf("parse %s: %w", src.ID(), err)
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
