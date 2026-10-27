// Package cmdb holds the use cases on CMDB Sources: testing a login,
// connecting one, showing the Connected CMDB Source, replacing its login,
// disconnecting it, syncing its Assets and listing the Customer's Assets.
package cmdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/cmdb/provider"
	"barbackend/internal/encryption"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

// ErrInvalidLogin is a login its CMDB Provider rejects without reaching the
// CMDB, such as a malformed URL, or one for an unknown provider.
var ErrInvalidLogin = errors.New("invalid cmdb source login")

var (
	// ErrNotConnected is a Customer with no Connected CMDB Source.
	ErrNotConnected = postgres.ErrNotConnected
	// ErrAlreadyConnected is a Customer that already has a Connected CMDB Source.
	ErrAlreadyConnected = postgres.ErrAlreadyConnected
	// ErrSyncInProgress is a Sync refused because another Sync of the same
	// CMDB Source holds its lock.
	ErrSyncInProgress = postgres.ErrSyncInProgress
	// ErrCustomerDeactivated is a Sync refused because the Customer is
	// deactivated.
	ErrCustomerDeactivated = postgres.ErrCustomerDeactivated
)

type (
	Login   = provider.Login
	Failure = provider.Failure
)

// SyncFailure is a failed Sync Run: when it finished and why.
type SyncFailure struct {
	At    time.Time
	Error string
}

// SyncError is a Sync that failed after reading its CMDB Source and was
// recorded as a failed Sync Run.
type SyncError struct{ Err error }

func (e *SyncError) Error() string { return e.Err.Error() }
func (e *SyncError) Unwrap() error { return e.Err }

// ConnectedSource is a Connected CMDB Source as a person sees it. It holds
// no secret.
type ConnectedSource struct {
	Provider inventory.CMDBProvider
	URL      string
	User     string
	// LastSync is when the latest successful Sync finished, zero if none did.
	LastSync time.Time
	// LastSyncFailure is set only while the latest Sync Run is a failed one.
	LastSyncFailure *SyncFailure
}

// Service connects CMDB Sources and syncs their Assets. It seals their
// credentials with key, so adapters only ever see them decrypted (ADR 0012).
type Service struct {
	db          *postgres.DB
	providers   provider.Providers
	key         encryption.Key
	lifetime    context.Context
	syncTimeout time.Duration
}

// New runs every Sync under lifetime, which ends when the server shuts down,
// and bounds it by syncTimeout.
func New(db *postgres.DB, providers provider.Providers, key encryption.Key, lifetime context.Context, syncTimeout time.Duration) *Service {
	return &Service{db: db, providers: providers, key: key, lifetime: lifetime, syncTimeout: syncTimeout}
}

// detach keeps a Sync running when its caller goes away, such as a client
// that closes the tab, since a Sync cut short only records a failure. It
// keeps the caller's values.
func (s *Service) detach(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.syncTimeout)
	stop := context.AfterFunc(s.lifetime, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func (s *Service) create(ctx context.Context, customer tenancy.CustomerID, name inventory.CMDBProvider, settings, credentials json.RawMessage) error {
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), customer, name)
	if err != nil {
		return err
	}
	sealed, err := s.seal(src.ID(), credentials)
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.CreateCMDBSource(ctx, src, settings, sealed) })
}

// TestLogin checks a login against its CMDB and stores nothing. A CMDB that
// cannot be reached or rejects the login is a *Failure.
func (s *Service) TestLogin(ctx context.Context, name inventory.CMDBProvider, login Login) error {
	_, _, err := s.checkLogin(ctx, name, login)
	return err
}

// Connect makes a login the Customer's Connected CMDB Source once its CMDB
// accepts it, then runs the first Sync. It stores nothing when the check
// fails, as TestLogin does. A failed first Sync is recorded and leaves the
// source connected, so it is shown as LastSyncFailure rather than returned:
// the admin fixes the CMDB and syncs again without reconnecting. Like
// SyncConnected, it outlives ctx.
func (s *Service) Connect(ctx context.Context, customer tenancy.CustomerID, name inventory.CMDBProvider, login Login) (ConnectedSource, error) {
	ctx, cancel := s.detach(ctx)
	defer cancel()
	settings, credentials, err := s.checkLogin(ctx, name, login)
	if err != nil {
		return ConnectedSource{}, err
	}
	if err := s.create(ctx, customer, name, settings, credentials); err != nil {
		return ConnectedSource{}, err
	}
	var failed *SyncError
	if _, err := s.syncConnected(ctx, customer); err != nil && !errors.As(err, &failed) {
		return ConnectedSource{}, err
	}
	return s.ConnectedSource(context.WithoutCancel(ctx), customer)
}

// UpdateLogin replaces the login of the Customer's Connected CMDB Source once
// its CMDB accepts it, keeping the source and so its Assets and their
// Declarations. It stores nothing when the check fails, and runs no Sync.
// The login is for the source's own CMDB Provider: another provider's Record
// IDs would not match the Assets.
func (s *Service) UpdateLogin(ctx context.Context, customer tenancy.CustomerID, login Login) (ConnectedSource, error) {
	stored, err := s.connected(ctx, customer)
	if err != nil {
		return ConnectedSource{}, err
	}
	src := stored.Source
	settings, credentials, err := s.checkLogin(ctx, src.Provider(), login)
	if err != nil {
		return ConnectedSource{}, err
	}
	sealed, err := s.seal(src.ID(), credentials)
	if err != nil {
		return ConnectedSource{}, err
	}
	if err := s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.UpdateConnectedLogin(ctx, src.ID(), settings, sealed) }); err != nil {
		return ConnectedSource{}, err
	}
	return s.ConnectedSource(ctx, customer)
}

// Disconnect makes the Customer's Connected CMDB Source a Disconnected one
// and its Assets Inactive, in one transaction. It fails with ErrNotConnected
// when there is none, and with ErrSyncInProgress while a Sync of it commits.
func (s *Service) Disconnect(ctx context.Context, customer tenancy.CustomerID) error {
	return s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.DisconnectCMDBSource(ctx, customer) })
}

func (s *Service) checkLogin(ctx context.Context, name inventory.CMDBProvider, login Login) (settings, credentials json.RawMessage, err error) {
	p, err := s.providers.Lookup(name)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidLogin, err)
	}
	settings, credentials, err = p.FromLogin(login)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidLogin, err)
	}
	parsed, err := p.ParseSettings(settings, credentials)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidLogin, err)
	}
	if err := parsed.CheckCredentials(ctx); err != nil {
		return nil, nil, err
	}
	return settings, credentials, nil
}

// ConnectedSource fails with ErrNotConnected when the Customer has no
// Connected CMDB Source. It reads only plain settings, so it needs no key.
func (s *Service) ConnectedSource(ctx context.Context, customer tenancy.CustomerID) (ConnectedSource, error) {
	var (
		stored postgres.StoredCMDBSource
		status postgres.SyncStatus
	)
	err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		var err error
		if stored, err = tx.ConnectedCMDBSource(ctx, customer); err != nil {
			return err
		}
		status, err = tx.SyncStatus(ctx, stored.Source.ID())
		return err
	})
	if err != nil {
		return ConnectedSource{}, err
	}
	src := stored.Source
	p, err := s.providers.Lookup(src.Provider())
	if err != nil {
		return ConnectedSource{}, err
	}
	desc, err := p.Describe(stored.Settings)
	if err != nil {
		return ConnectedSource{}, fmt.Errorf("describe %s: %w", src.ID(), err)
	}
	connected := ConnectedSource{Provider: src.Provider(), URL: desc.URL, User: desc.User, LastSync: status.LastSync}
	if f := status.LastFailure; f != nil {
		connected.LastSyncFailure = &SyncFailure{At: f.At, Error: f.Error}
	}
	return connected, nil
}

func (s *Service) connected(ctx context.Context, customer tenancy.CustomerID) (postgres.StoredCMDBSource, error) {
	var stored postgres.StoredCMDBSource
	err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		var err error
		stored, err = tx.ConnectedCMDBSource(ctx, customer)
		return err
	})
	return stored, err
}

func (s *Service) seal(id inventory.CMDBSourceID, credentials json.RawMessage) ([]byte, error) {
	sealed, err := s.key.Seal(credentials, owner(id))
	if err != nil {
		return nil, fmt.Errorf("seal credentials: %w", err)
	}
	return sealed, nil
}

// open is the stored source as its CMDB Provider reads it, with its
// credentials decrypted.
func (s *Service) open(stored postgres.StoredCMDBSource) (provider.Settings, error) {
	src := stored.Source
	p, err := s.providers.Lookup(src.Provider())
	if err != nil {
		return nil, err
	}
	credentials, err := s.key.Open(stored.Credentials, owner(src.ID()))
	if err != nil {
		return nil, fmt.Errorf("credentials of %s: %w", src.ID(), err)
	}
	parsed, err := p.ParseSettings(stored.Settings, credentials)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", src.ID(), err)
	}
	return parsed, nil
}

func owner(id inventory.CMDBSourceID) []byte {
	return []byte(id.String())
}

// SyncConnected brings the Assets of the Customer's Connected CMDB Source in
// line with a full snapshot of it. It fails with ErrNotConnected when the
// Customer has none, including when the source is disconnected while the Sync
// runs. Every failure after the source is read is recorded as a failed Sync
// Run, which changed no Asset, and returned as a *SyncError. A Sync refused
// with ErrSyncInProgress is not recorded: it would report the running Sync as
// failed, and recording it would wait for that Sync to release the source.
// Nor is one that lost the source to a disconnect, which changed nothing, or
// one refused with ErrCustomerDeactivated, since the Customer is no longer
// served.
// The Sync outlives ctx: it ends when the Service's lifetime does, or at its
// time limit.
func (s *Service) SyncConnected(ctx context.Context, customer tenancy.CustomerID) (inventory.SyncRun, error) {
	ctx, cancel := s.detach(ctx)
	defer cancel()
	return s.syncConnected(ctx, customer)
}

func (s *Service) syncConnected(ctx context.Context, customer tenancy.CustomerID) (inventory.SyncRun, error) {
	started := time.Now()
	stored, err := s.connected(ctx, customer)
	if err != nil {
		return inventory.SyncRun{}, err
	}
	run, err := s.sync(ctx, stored, started)
	switch {
	case errors.Is(err, postgres.ErrDisconnected):
		return inventory.SyncRun{}, fmt.Errorf("%w: %w", ErrNotConnected, err)
	case errors.Is(err, ErrSyncInProgress), errors.Is(err, ErrCustomerDeactivated):
		return inventory.SyncRun{}, err
	case err != nil:
		return inventory.SyncRun{}, s.recordFailure(ctx, stored.Source.ID(), started, err)
	}
	return run, nil
}

func (s *Service) sync(ctx context.Context, stored postgres.StoredCMDBSource, started time.Time) (inventory.SyncRun, error) {
	src := stored.Source
	parsed, err := s.open(stored)
	if err != nil {
		return inventory.SyncRun{}, err
	}
	snapshot, err := parsed.Snapshot(ctx)
	if err != nil {
		return inventory.SyncRun{}, fmt.Errorf("snapshot of %s: %w", src.ID(), err)
	}
	return s.db.CommitSync(ctx, src.ID(), started, func(existing []*inventory.Asset) (inventory.Reconciliation, error) {
		return inventory.Reconcile(src.ID(), existing, snapshot)
	})
}

func (s *Service) recordFailure(ctx context.Context, id inventory.CMDBSourceID, started time.Time, cause error) error {
	ctx = context.WithoutCancel(ctx)
	run, err := inventory.FailedRun(id, started, time.Now(), cause)
	if err == nil {
		err = s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.RecordFailedSync(ctx, run) })
	}
	if err != nil {
		return fmt.Errorf("%v; record failed sync run: %w", cause, err)
	}
	return &SyncError{Err: cause}
}
