package cmdb_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"barbackend/internal/cmdb/provider/providertest"
	"barbackend/internal/inventory"
)

// syncedSources records the CMDB Sources OnSynced was called with.
type syncedSources struct {
	mu      sync.Mutex
	sources []inventory.CMDBSourceID
	err     error
}

func (s *syncedSources) hook(_ context.Context, source inventory.CMDBSourceID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, source)
	return s.err
}

func (s *syncedSources) calls() []inventory.CMDBSourceID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]inventory.CMDBSourceID{}, s.sources...)
}

func TestOnSyncedRunsAfterEverySyncThatCommits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	synced := &syncedSources{}
	e.cmdb.OnSynced(synced.hook)

	customer, source := e.connect(t)
	if _, err := e.cmdb.SyncConnected(context.Background(), viewerOf(customer)); err != nil {
		t.Fatal(err)
	}

	if got := synced.calls(); len(got) != 2 || got[0] != source || got[1] != source {
		t.Errorf("OnSynced calls = %v, want the first Sync of Connect and the later one, both of %v", got, source)
	}
}

func TestOnSyncedDoesNotRunAfterAFailedSync(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	synced := &syncedSources{}
	e.cmdb.OnSynced(synced.hook)
	e.provider.Err = errors.New("cmdb is down")

	customer := e.newCustomer(t)
	if _, err := e.cmdb.Connect(context.Background(), viewerOf(customer), providertest.Name, providertest.Login); err != nil {
		t.Fatal(err)
	}

	if got := synced.calls(); len(got) != 0 {
		t.Errorf("OnSynced calls = %v, want none for a Sync that failed", got)
	}
}

func TestOnSyncedErrorLeavesTheSyncSucceeded(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	synced := &syncedSources{err: errors.New("findings are down")}
	e.cmdb.OnSynced(synced.hook)

	customer, _ := e.connect(t)
	if _, err := e.cmdb.SyncConnected(context.Background(), viewerOf(customer)); err != nil {
		t.Errorf("SyncConnected = %v, want the Sync to succeed whatever OnSynced returns", err)
	}
	if n := e.failedRuns(t); n != 0 {
		t.Errorf("failed Sync Runs = %d, want none", n)
	}
}
