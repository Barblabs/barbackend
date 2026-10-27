package cmdb_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/provider"
	"barbackend/internal/cmdb/provider/providertest"
	"barbackend/internal/encryption"
	"barbackend/internal/inventory"
)

var rejected = &provider.Failure{Code: provider.InvalidCredentials, Message: "the cmdb rejected the user or password"}

func TestTestLoginStoresNothing(t *testing.T) {
	t.Parallel()
	for _, checkErr := range []error{nil, rejected} {
		e := newEnv(t)
		e.provider.CheckErr = checkErr

		if err := e.cmdb.TestLogin(context.Background(), providertest.Name, providertest.Login); !errors.Is(err, checkErr) {
			t.Errorf("err = %v, want %v", err, checkErr)
		}
		if n := e.queryInt(t, "SELECT count(*) FROM cmdb_sources"); n != 0 {
			t.Errorf("check result %v: stored sources = %d, want 0", checkErr, n)
		}
	}
}

func TestConnectRunsTheFirstSync(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}
	customer := e.newCustomer(t)

	got, err := e.cmdb.Connect(context.Background(), customer, providertest.Name, providertest.Login)

	if err != nil {
		t.Fatal(err)
	}
	if got.LastSync.IsZero() || got.LastSyncFailure != nil {
		t.Errorf("connected source = %+v, want a last Sync and no failure", got)
	}
	if assets := e.assets(t, e.connected(t, customer).Source.ID()); len(assets) != 1 || assets[0].Imported().Name() != "vm-a" {
		t.Errorf("assets = %+v, want vm-a imported by the first Sync", assets)
	}
}

func TestConnectThatFailsStoresNothing(t *testing.T) {
	tests := []struct {
		name     string
		noKey    bool
		checkErr error
		want     error
	}{
		{name: "rejected login", checkErr: rejected, want: rejected},
		{name: "no key", noKey: true, want: encryption.ErrNoKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.provider.CheckErr = tt.checkErr
			svc := e.cmdb
			if tt.noKey {
				svc = e.withKey(encryption.Key{})
			}

			_, err := svc.Connect(context.Background(), e.newCustomer(t), providertest.Name, providertest.Login)

			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			if n := e.queryInt(t, "SELECT count(*) FROM cmdb_sources"); n != 0 {
				t.Errorf("stored sources = %d, want 0", n)
			}
		})
	}
}

func TestConnectWithFailedFirstSyncStaysConnected(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Err = errors.New("cmdb unreachable")
	customer := e.newCustomer(t)

	got, err := e.cmdb.Connect(context.Background(), customer, providertest.Name, providertest.Login)

	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSync.IsZero() || got.LastSyncFailure == nil || !strings.Contains(got.LastSyncFailure.Error, "cmdb unreachable") {
		t.Errorf("connected source = %+v, want no last Sync and the failure", got)
	}
	e.provider.Err = nil
	if _, err := e.cmdb.SyncConnected(context.Background(), customer); err != nil {
		t.Errorf("a later Sync: %v, want success since the source stays connected", err)
	}
}

func TestConnectOutlivesItsCaller(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	closedTab, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := e.cmdb.Connect(closedTab, e.newCustomer(t), providertest.Name, providertest.Login)

	if err != nil {
		t.Fatal(err)
	}
	if got.LastSync.IsZero() || got.LastSyncFailure != nil {
		t.Errorf("connected source = %+v, want a successful first Sync", got)
	}
}

func TestConnectWithFirstSyncExceedingTheTimeLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Hanging = make(chan struct{})

	got, err := e.withSyncLimits(context.Background(), 50*time.Millisecond).Connect(context.Background(), e.newCustomer(t), providertest.Name, providertest.Login)

	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSync.IsZero() || got.LastSyncFailure == nil || !strings.Contains(got.LastSyncFailure.Error, context.DeadlineExceeded.Error()) {
		t.Errorf("connected source = %+v, want no last Sync and the deadline as the failure", got)
	}
}

func TestConnectWhenAlreadyConnected(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, _ := e.connect(t)
	other := providertest.Login
	other.URL = "http://other-cmdb"

	_, err := e.cmdb.Connect(context.Background(), customer, providertest.Name, other)

	if !errors.Is(err, cmdb.ErrAlreadyConnected) {
		t.Errorf("err = %v, want ErrAlreadyConnected", err)
	}
	if got := e.connectedSource(t, customer); got.URL != providertest.Login.URL {
		t.Errorf("connected url = %s, want the source connected first %s", got.URL, providertest.Login.URL)
	}
}

func TestConnectStoresSealedCredentials(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, _ := e.connect(t)

	if stored := e.connected(t, customer); len(stored.Credentials) == 0 || bytes.Contains(stored.Credentials, []byte(providertest.Secret)) {
		t.Errorf("stored credentials = %q, want ciphertext without the password", stored.Credentials)
	}
}

func TestConnectAfterDisconnectCreatesANewCMDBSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}
	customer, old := e.connect(t)
	if err := e.cmdb.Disconnect(context.Background(), customer); err != nil {
		t.Fatal(err)
	}

	if _, err := e.cmdb.Connect(context.Background(), customer, providertest.Name, providertest.Login); err != nil {
		t.Fatal(err)
	}

	current := e.connected(t, customer).Source.ID()
	if current == old {
		t.Errorf("connected source = %s, want a new one", current)
	}
	if got := e.rows(t, "SELECT cmdb_source_id::text, record_id, inactive_since IS NOT NULL FROM assets ORDER BY inactive_since IS NOT NULL"); !reflect.DeepEqual(got, [][]string{
		{current.String(), "a", "false"},
		{old.String(), "a", "true"},
	}) {
		t.Errorf("assets = %v, want a new Active one and the old one still Inactive", got)
	}
}

func TestConnectedSourceReportsLatestSyncRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, _ := e.connect(t)

	succeeded, err := e.cmdb.SyncConnected(context.Background(), customer)
	if err != nil {
		t.Fatal(err)
	}
	lastSync := succeeded.Finished().Truncate(time.Microsecond)
	if got := e.connectedSource(t, customer); !got.LastSync.Equal(lastSync) || got.LastSyncFailure != nil {
		t.Errorf("after a successful Sync: %+v, want last Sync %v and no failure", got, lastSync)
	}

	e.provider.Err = errors.New("cmdb unreachable")
	beforeFailure := time.Now().Truncate(time.Microsecond)
	if _, err := e.cmdb.SyncConnected(context.Background(), customer); err == nil {
		t.Fatal("Sync succeeded, want a failure")
	}
	got := e.connectedSource(t, customer)
	if !got.LastSync.Equal(lastSync) {
		t.Errorf("after a failed Sync: last Sync = %v, want still %v", got.LastSync, lastSync)
	}
	if f := got.LastSyncFailure; f == nil || f.At.Before(beforeFailure) || !strings.Contains(f.Error, "cmdb unreachable") {
		t.Errorf("after a failed Sync: failure = %+v, want the failure", f)
	}

	e.provider.Err = nil
	if _, err := e.cmdb.SyncConnected(context.Background(), customer); err != nil {
		t.Fatal(err)
	}
	if got := e.connectedSource(t, customer); got.LastSyncFailure != nil {
		t.Errorf("after a later successful Sync: failure = %+v, want none", got.LastSyncFailure)
	}
}

var rotated = provider.Login{URL: "http://new-cmdb", User: "new-admin", Password: "new-secret"}

func TestUpdateLogin(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, src := e.connect(t)
	synced, err := e.cmdb.SyncConnected(context.Background(), customer)
	if err != nil {
		t.Fatal(err)
	}

	got, err := e.cmdb.UpdateLogin(context.Background(), customer, rotated)

	if err != nil {
		t.Fatal(err)
	}
	if got.URL != rotated.URL || got.User != rotated.User {
		t.Errorf("connected source = %+v, want the new url and user", got)
	}
	if lastSync := synced.Finished().Truncate(time.Microsecond); !got.LastSync.Equal(lastSync) {
		t.Errorf("last Sync = %v, want still %v, since the Sync history stays and the update runs no Sync", got.LastSync, lastSync)
	}
	if id := e.connected(t, customer).Source.ID(); id != src {
		t.Errorf("connected source = %s, want the same source %s", id, src)
	}
	if _, err := e.cmdb.SyncConnected(context.Background(), customer); err != nil || e.provider.Secret != rotated.Password {
		t.Errorf("a later Sync: %v with secret %q, want success with the new password", err, e.provider.Secret)
	}
}

func TestUpdateLoginWithRejectedCredentials(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, _ := e.connect(t)
	before := e.connected(t, customer)
	e.provider.CheckErr = rejected

	_, err := e.cmdb.UpdateLogin(context.Background(), customer, rotated)

	if !errors.Is(err, rejected) {
		t.Errorf("err = %v, want %v", err, rejected)
	}
	if after := e.connected(t, customer); !bytes.Equal(after.Settings, before.Settings) || !bytes.Equal(after.Credentials, before.Credentials) {
		t.Errorf("stored source = %s %x, want unchanged %s %x", after.Settings, after.Credentials, before.Settings, before.Credentials)
	}
}

func TestUpdateLoginKeepsAssetsAndDeclarations(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a")}}
	customer, src := e.connect(t)
	if _, err := e.conn.Exec(context.Background(), "UPDATE assets SET declared_exposure_id = $1", int16(inventory.Internal)); err != nil {
		t.Fatal(err)
	}
	assets := func() [][]string {
		return e.rows(t, "SELECT record_id, name, declared_exposure_id FROM assets WHERE cmdb_source_id = $1 ORDER BY record_id", src.String())
	}
	before := assets()

	if _, err := e.cmdb.UpdateLogin(context.Background(), customer, rotated); err != nil {
		t.Fatal(err)
	}

	if after := assets(); !reflect.DeepEqual(after, before) {
		t.Errorf("assets = %v, want unchanged %v", after, before)
	}
}

func TestDisconnect(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "a", "vm-a"), record(t, "b", "vm-b")}}
	customer, src := e.connect(t)

	if err := e.cmdb.Disconnect(context.Background(), customer); err != nil {
		t.Fatal(err)
	}

	if _, err := e.cmdb.ConnectedSource(context.Background(), customer); !errors.Is(err, cmdb.ErrNotConnected) {
		t.Errorf("connected source err = %v, want ErrNotConnected", err)
	}
	if got := e.rows(t, "SELECT record_id, inactive_since IS NOT NULL FROM assets WHERE cmdb_source_id = $1 ORDER BY record_id", src.String()); !reflect.DeepEqual(got, [][]string{{"a", "true"}, {"b", "true"}}) {
		t.Errorf("assets = %v, want a and b stored and Inactive", got)
	}
	if got := e.rows(t, "SELECT disconnected_at IS NOT NULL FROM cmdb_sources WHERE id = $1", src.String()); !reflect.DeepEqual(got, [][]string{{"true"}}) {
		t.Errorf("cmdb source = %v, want it stored and disconnected", got)
	}
}

func TestDisconnectWhileASyncRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	customer, src := e.connect(t)
	release := e.holdSyncLock(t, src)

	err := e.cmdb.Disconnect(context.Background(), customer)
	release()

	if !errors.Is(err, cmdb.ErrSyncInProgress) {
		t.Errorf("err = %v, want ErrSyncInProgress", err)
	}
	if id := e.connected(t, customer).Source.ID(); id != src {
		t.Errorf("connected source = %s, want %s still connected", id, src)
	}
}
