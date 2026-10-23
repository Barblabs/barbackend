// Package sources holds the use cases on CMDB Sources: testing a login,
// connecting or adding one, showing the Connected CMDB Source, replacing its
// login, disconnecting it and syncing its Assets.
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

// ErrInvalidLogin is a login its CMDB Provider rejects without reaching the
// CMDB, such as a malformed URL, or one for an unknown provider.
var ErrInvalidLogin = errors.New("invalid cmdb source login")

// The errors, seam types and Sync status below belong to persistence and the
// CMDB Provider seam, named here so that transports, which only import use
// cases (ADR 0008), can use them.
var (
	// ErrNotConnected is a Customer with no Connected CMDB Source.
	ErrNotConnected = postgres.ErrNotConnected
	// ErrAlreadyConnected is a Customer that already has a Connected CMDB Source.
	ErrAlreadyConnected = postgres.ErrAlreadyConnected
	// ErrSyncInProgress is a Sync refused because another Sync of the same
	// CMDB Source holds its lock.
	ErrSyncInProgress = postgres.ErrSyncInProgress
	// ErrDisconnected is a Sync refused because its CMDB Source is a
	// Disconnected CMDB Source.
	ErrDisconnected = postgres.ErrDisconnected
)

type (
	Login       = cmdb.Login
	Failure     = cmdb.Failure
	SyncFailure = postgres.SyncFailure
)

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
	return s.create(ctx, customer, provider, settings, credentials)
}

// create stores a new CMDB Source with sealed credentials, without checking
// them: callers have.
func (s *Service) create(ctx context.Context, customer inventory.CustomerID, provider inventory.CMDBProvider, settings, credentials json.RawMessage) (inventory.CMDBSource, error) {
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

// TestLogin checks a login against its CMDB and stores nothing. A CMDB that
// cannot be reached or rejects the login is a *Failure.
func (s *Service) TestLogin(ctx context.Context, provider inventory.CMDBProvider, login Login) error {
	_, _, err := s.checkLogin(ctx, provider, login)
	return err
}

// Connect makes a login the Customer's Connected CMDB Source once its CMDB
// accepts it, then runs the first Sync. It stores nothing when the check
// fails, as TestLogin does. A failed first Sync is recorded and leaves the
// source connected, so it is shown as LastSyncFailure rather than returned:
// the admin fixes the CMDB and syncs again without reconnecting.
func (s *Service) Connect(ctx context.Context, customer inventory.CustomerID, provider inventory.CMDBProvider, login Login) (ConnectedSource, error) {
	settings, credentials, err := s.checkLogin(ctx, provider, login)
	if err != nil {
		return ConnectedSource{}, err
	}
	src, err := s.create(ctx, customer, provider, settings, credentials)
	if err != nil {
		return ConnectedSource{}, err
	}
	var failed *SyncError
	if _, err := s.Sync(ctx, src.ID()); err != nil && !errors.As(err, &failed) {
		return ConnectedSource{}, err
	}
	// A Sync that failed because ctx ended still connected the source, so
	// reading it must not fail for the same reason.
	return s.ConnectedSource(context.WithoutCancel(ctx), customer)
}

// UpdateLogin replaces the login of the Customer's Connected CMDB Source once
// its CMDB accepts it, keeping the source and so its Assets and their
// Declarations. It stores nothing when the check fails, and runs no Sync.
// The login is for the source's own CMDB Provider: another provider's Record
// IDs would not match the Assets.
func (s *Service) UpdateLogin(ctx context.Context, customer inventory.CustomerID, login Login) (ConnectedSource, error) {
	stored, err := s.connected(ctx, customer)
	if err != nil {
		return ConnectedSource{}, err
	}
	src := stored.Source
	settings, credentials, err := s.checkLogin(ctx, src.Provider(), login)
	if err != nil {
		return ConnectedSource{}, err
	}
	sealed, err := s.key.Seal(credentials, owner(src.ID()))
	if err != nil {
		return ConnectedSource{}, fmt.Errorf("seal credentials: %w", err)
	}
	if err := s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.UpdateConnectedLogin(ctx, src.ID(), settings, sealed) }); err != nil {
		return ConnectedSource{}, err
	}
	return s.ConnectedSource(ctx, customer)
}

// Disconnect makes the Customer's Connected CMDB Source a Disconnected one
// and its Assets Inactive, in one transaction. It fails with ErrNotConnected
// when there is none, and with ErrSyncInProgress while a Sync of it commits.
func (s *Service) Disconnect(ctx context.Context, customer inventory.CustomerID) error {
	return s.db.InTx(ctx, func(tx *postgres.Tx) error { return tx.DisconnectCMDBSource(ctx, customer) })
}

// checkLogin turns a login into the settings and credentials its CMDB
// accepted.
func (s *Service) checkLogin(ctx context.Context, provider inventory.CMDBProvider, login Login) (settings, credentials json.RawMessage, err error) {
	p, err := s.providers.Lookup(provider)
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
func (s *Service) ConnectedSource(ctx context.Context, customer inventory.CustomerID) (ConnectedSource, error) {
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
	return ConnectedSource{
		Provider:        src.Provider(),
		URL:             desc.URL,
		User:            desc.User,
		LastSync:        status.LastSync,
		LastSyncFailure: status.LastFailure,
	}, nil
}

// connected reads the Customer's Connected CMDB Source, failing with
// ErrNotConnected when there is none.
func (s *Service) connected(ctx context.Context, customer inventory.CustomerID) (postgres.StoredCMDBSource, error) {
	var stored postgres.StoredCMDBSource
	err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		var err error
		stored, err = tx.ConnectedCMDBSource(ctx, customer)
		return err
	})
	return stored, err
}

// owner binds credentials to their CMDB Source, so sealed credentials copied
// to another source fail to open.
func owner(id inventory.CMDBSourceID) []byte {
	return []byte(id.String())
}

// SyncConnected syncs the Customer's Connected CMDB Source as Sync does. It
// fails with ErrNotConnected when the Customer has none.
func (s *Service) SyncConnected(ctx context.Context, customer inventory.CustomerID) (inventory.SyncRun, error) {
	stored, err := s.connected(ctx, customer)
	if err != nil {
		return inventory.SyncRun{}, err
	}
	return s.Sync(ctx, stored.Source.ID())
}

// Sync brings the Assets of a CMDB Source in line with a full snapshot of it.
// Every failure after the source is read is recorded as a failed Sync Run,
// which changed no Asset, and returned as a *SyncError. A Sync refused with
// ErrSyncInProgress is not recorded: it would report the running Sync as
// failed, and recording it would wait for that Sync to release the source.
// Nor is a Sync refused with ErrDisconnected, which never ran: the source was
// disconnected before it read the CMDB or committed.
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
	// Refused before reading the CMDB, which the admin may have disconnected
	// to stop barbattack using its credentials.
	if !stored.Connected {
		return inventory.SyncRun{}, fmt.Errorf("%w: %s", ErrDisconnected, id)
	}
	run, err := s.sync(ctx, stored, started)
	if errors.Is(err, ErrSyncInProgress) || errors.Is(err, ErrDisconnected) {
		return inventory.SyncRun{}, err
	}
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
// cancellation may be the failure being recorded. Only a recorded failure is
// a *SyncError; failing to record it is an error of barbackend, so the cause
// is kept only as text and is not reported as the CMDB's failure.
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
