package assets_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"barbackend/internal/assets"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

// rescorer records the Assets it is asked to rescore and fails with err.
type rescorer struct {
	rescored []inventory.SourceReference
	err      error
}

func (r *rescorer) RescoreAsset(_ context.Context, asset inventory.SourceReference) error {
	r.rescored = append(r.rescored, asset)
	return r.err
}

// env is one Customer with a Customer Admin and a CMDB Source holding one
// Active Virtual Machine, "vm", and one Inactive one, "gone".
type env struct {
	db       *postgres.DB
	rescorer *rescorer
	assets   *assets.Service
	customer tenancy.CustomerID
	admin    tenancy.User
}

func newEnv(t *testing.T) env {
	t.Helper()
	db := pgtest.NewDB(t)
	r := &rescorer{}
	e := env{db: db, rescorer: r, assets: assets.New(db, r), customer: newCustomer(t, db)}
	e.admin = e.storeUser(t, tenancy.CustomerAdmin)
	connect(t, db, e.customer, map[string]bool{"vm": true, "gone": false})
	return e
}

func inTx(t *testing.T, db *postgres.DB, fn func(*postgres.Tx) error) {
	t.Helper()
	if err := db.InTx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func newCustomer(t *testing.T, db *postgres.DB) tenancy.CustomerID {
	t.Helper()
	id := tenancy.CustomerID(uuid.New())
	c, err := tenancy.NewCustomer(id, id.String())
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error {
		_, err := tx.CreateCustomer(context.Background(), c)
		return err
	})
	return id
}

func (e env) storeUser(t *testing.T, role tenancy.Role) tenancy.User {
	t.Helper()
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), uuid.NewString()+"@example.com", role, e.customer)
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, e.db, func(tx *postgres.Tx) error {
		return pgtest.CreateUser(context.Background(), tx, u, uuid.NewString())
	})
	return u
}

// connect syncs into a new CMDB Source of customer one Virtual Machine per
// record id, Active or not.
func connect(t *testing.T, db *postgres.DB, customer tenancy.CustomerID, active map[string]bool) {
	t.Helper()
	src, err := inventory.NewCMDBSource(inventory.CMDBSourceID(uuid.New()), customer, "itop")
	if err != nil {
		t.Fatal(err)
	}
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.CreateCMDBSource(context.Background(), src, []byte(`{}`), []byte{})
	})
	var records []inventory.Record
	for id, isActive := range active {
		imported, err := inventory.NewImportedAsset(inventory.ImportedAssetParams{Name: id, Kind: inventory.VirtualMachine, Retired: !isActive})
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, inventory.Record{RecordID: id, Imported: imported})
	}
	_, err = db.CommitSync(context.Background(), src.ID(), time.Now(), func(existing inventory.Stored) (inventory.Reconciliation, error) {
		return inventory.Reconcile(src.ID(), existing, inventory.Snapshot{Records: records})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// asset is the Customer's Asset with that record id, as the list reads it.
func (e env) asset(t *testing.T, record string) assets.StoredAsset {
	t.Helper()
	return assetOf(t, e.assets, e.customer, record)
}

func assetOf(t *testing.T, svc *assets.Service, customer tenancy.CustomerID, record string) assets.StoredAsset {
	t.Helper()
	viewer, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "viewer@example.com", tenancy.Viewer, customer)
	if err != nil {
		t.Fatal(err)
	}
	page, err := svc.List(context.Background(), viewer, assets.Query{})
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(page.Assets, func(a assets.StoredAsset) bool { return a.Asset.Ref().RecordID == record })
	if i < 0 {
		t.Fatalf("no asset %q", record)
	}
	return page.Assets[i]
}

// scoredDeclaration is a value a Customer Admin declares over an Asset and
// that the Score reads, so declaring and clearing it rescores the Asset.
type scoredDeclaration struct {
	name     string
	declare  func(e env, id int64) (assets.StoredAsset, error)
	clear    func(e env, id int64) (assets.StoredAsset, error)
	declared func(assets.StoredAsset) bool
	cleared  func(assets.StoredAsset) bool
	audit    func(assets.StoredAsset) postgres.DeclarationAudit
}

var scoredDeclarations = []scoredDeclaration{
	{
		name: "exposure",
		declare: func(e env, id int64) (assets.StoredAsset, error) {
			return e.assets.DeclareExposure(context.Background(), e.admin, id, inventory.Internal)
		},
		clear: func(e env, id int64) (assets.StoredAsset, error) {
			return e.assets.ClearExposure(context.Background(), e.admin, id)
		},
		declared: func(a assets.StoredAsset) bool { return a.Asset.Exposure() == inventory.Internal },
		cleared:  func(a assets.StoredAsset) bool { return a.Asset.Exposure() == inventory.ExposureUnknown },
		audit:    func(a assets.StoredAsset) postgres.DeclarationAudit { return a.ExposureAudit },
	},
	{
		name: "information classification",
		declare: func(e env, id int64) (assets.StoredAsset, error) {
			return e.assets.DeclareInformationClassification(context.Background(), e.admin, id, inventory.ClassifiedConfidential)
		},
		clear: func(e env, id int64) (assets.StoredAsset, error) {
			return e.assets.ClearInformationClassification(context.Background(), e.admin, id)
		},
		declared: func(a assets.StoredAsset) bool {
			return a.Asset.InformationClassification() == inventory.ClassifiedConfidential
		},
		cleared: func(a assets.StoredAsset) bool { return a.Asset.InformationClassification() == inventory.Unclassified },
		audit:   func(a assets.StoredAsset) postgres.DeclarationAudit { return a.InformationClassificationAudit },
	},
}

func TestAScoredDeclarationIsStoredClearedAndRescoredEachTime(t *testing.T) {
	t.Parallel()
	for _, d := range scoredDeclarations {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			vm := e.asset(t, "vm")

			got, err := d.declare(e, vm.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !d.declared(got) || d.audit(got).By != e.admin.Email() {
				t.Errorf("returned %+v declared %+v, want the caller's Declaration by %s", got.Asset, d.audit(got), e.admin.Email())
			}
			if stored := e.asset(t, "vm"); !d.declared(stored) {
				t.Errorf("stored %+v, want the Declaration", stored.Asset)
			}
			if want := []inventory.SourceReference{vm.Asset.Ref()}; !slices.Equal(e.rescorer.rescored, want) {
				t.Errorf("rescored %v, want %v", e.rescorer.rescored, want)
			}

			got, err = d.clear(e, vm.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !d.cleared(got) || d.audit(got) != (postgres.DeclarationAudit{}) {
				t.Errorf("cleared %+v declared %+v, want no Declaration", got.Asset, d.audit(got))
			}
			if len(e.rescorer.rescored) != 2 {
				t.Errorf("rescored %d times, want once per change", len(e.rescorer.rescored))
			}
		})
	}
}

func TestADeclarationStandsWhenRescoringFails(t *testing.T) {
	t.Parallel()
	for _, d := range scoredDeclarations {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.rescorer.err = errors.New("database went away")
			vm := e.asset(t, "vm")

			if _, err := d.declare(e, vm.ID); !errors.Is(err, e.rescorer.err) {
				t.Fatalf("err = %v, want the rescoring failure", err)
			}
			if stored := e.asset(t, "vm"); !d.declared(stored) {
				t.Errorf("stored %+v, want the Declaration made before rescoring failed", stored.Asset)
			}
		})
	}
}
