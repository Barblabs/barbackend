package inventory_test

import (
	"errors"
	"reflect"
	"testing"

	"barbackend/internal/inventory"
	"github.com/google/uuid"
)

type stored struct {
	id     string
	params inventory.ImportedAssetParams
	active bool
}

// change is an inventory.Change reduced to what the tests compare.
type change struct {
	id                                      string
	created, importedChanged, activeChanged bool
	activeAfter                             bool
	nameAfter                               string
}

func TestReconcile(t *testing.T) {
	osc := inventory.SoftwareComponent{Role: inventory.OperatingSystem, Name: "Ubuntu", Version: "22.04"}
	app := inventory.SoftwareComponent{Role: inventory.Application, Name: "nginx", Version: "1.24"}
	identified := app
	identified.Product = &inventory.Product{Vendor: "f5", Name: "nginx"}

	base := validParams()
	renamed := with(base, func(p *inventory.ImportedAssetParams) { p.Name = "srv-01-renamed" })
	retired := with(base, func(p *inventory.ImportedAssetParams) { p.Retired = true })
	software := with(base, func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{osc, app} })
	reordered := with(base, func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{app, osc} })
	duplicated := with(base, func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{osc, app, app} })
	identifiedSoftware := with(base, func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{osc, identified} })
	hardware := with(base, func(p *inventory.ImportedAssetParams) {
		p.Hardware = &inventory.Hardware{Vendor: "Dell", Model: "R740"}
	})
	otherHardware := with(base, func(p *inventory.ImportedAssetParams) { p.Hardware = &inventory.Hardware{Vendor: "HP", Model: "R740"} })

	tests := []struct {
		name       string
		existing   []stored
		records    map[string]inventory.ImportedAssetParams
		rejections []string
		want       []change
	}{
		{"new", nil, recs("1", base), nil,
			[]change{{id: "1", created: true, activeAfter: true, nameAfter: "srv-01"}}},
		{"new and retired is created inactive", nil, recs("1", retired), nil,
			[]change{{id: "1", created: true, activeAfter: false, nameAfter: "srv-01"}}},
		{"changed", []stored{{"1", base, true}}, recs("1", renamed), nil,
			[]change{{id: "1", importedChanged: true, activeAfter: true, nameAfter: "srv-01-renamed"}}},
		{"unchanged", []stored{{"1", base, true}}, recs("1", base), nil, nil},
		{"software reordered is unchanged", []stored{{"1", software, true}}, recs("1", reordered), nil, nil},
		{"duplicate software component is a change", []stored{{"1", software, true}}, recs("1", duplicated), nil,
			[]change{{id: "1", importedChanged: true, activeAfter: true, nameAfter: "srv-01"}}},
		{"identified product is a change", []stored{{"1", software, true}}, recs("1", identifiedSoftware), nil,
			[]change{{id: "1", importedChanged: true, activeAfter: true, nameAfter: "srv-01"}}},
		{"hardware vendor is a change", []stored{{"1", hardware, true}}, recs("1", otherHardware), nil,
			[]change{{id: "1", importedChanged: true, activeAfter: true, nameAfter: "srv-01"}}},
		{"retired", []stored{{"1", base, true}}, recs("1", retired), nil,
			[]change{{id: "1", importedChanged: true, activeChanged: true, activeAfter: false, nameAfter: "srv-01"}}},
		{"missing", []stored{{"1", base, true}}, nil, nil,
			[]change{{id: "1", activeChanged: true, activeAfter: false, nameAfter: "srv-01"}}},
		{"missing and already inactive", []stored{{"1", base, false}}, nil, nil, nil},
		{"reappearing", []stored{{"1", base, false}}, recs("1", base), nil,
			[]change{{id: "1", activeChanged: true, activeAfter: true, nameAfter: "srv-01"}}},
		{"un-retired", []stored{{"1", retired, false}}, recs("1", base), nil,
			[]change{{id: "1", importedChanged: true, activeChanged: true, activeAfter: true, nameAfter: "srv-01"}}},
		{"retired and already inactive", []stored{{"1", retired, false}}, recs("1", retired), nil, nil},
		{"rejected but existing", []stored{{"1", base, true}}, nil, []string{"1"}, nil},
		{"rejected and new", nil, nil, []string{"1"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := inventory.Reconcile(sourceID, storedAssets(t, tt.existing), snapshot(t, tt.records, tt.rejections...))
			if err != nil {
				t.Fatal(err)
			}
			var got []change
			for _, c := range r.Changes() {
				got = append(got, change{
					id: c.Asset.Ref().RecordID, created: c.Created, importedChanged: c.ImportedChanged,
					activeChanged: c.ActiveChanged, activeAfter: c.Asset.Active(), nameAfter: c.Asset.Imported().Name(),
				})
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("changes = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReconciliationCountsAndRejections(t *testing.T) {
	base := validParams()
	retired := with(base, func(p *inventory.ImportedAssetParams) { p.Retired = true })
	renamed := with(base, func(p *inventory.ImportedAssetParams) { p.Name = "renamed" })
	existing := storedAssets(t, []stored{
		{"changed", base, true},
		{"retired", base, true},
		{"missing", base, true},
		{"reappearing", base, false},
		{"rejected", base, true},
	})
	s := snapshot(t, map[string]inventory.ImportedAssetParams{
		"new": base, "changed": renamed, "retired": retired, "reappearing": base,
	}, "rejected", "rejected-new")

	r, err := inventory.Reconcile(sourceID, existing, s)
	if err != nil {
		t.Fatal(err)
	}
	want := inventory.SyncCounts{Created: 1, Updated: 2, Deactivated: 2, Reactivated: 1, Skipped: 2}
	if got := r.Counts(); got != want {
		t.Errorf("Counts() = %+v, want %+v", got, want)
	}
	if got := r.Rejections(); !reflect.DeepEqual(got, s.Rejections) {
		t.Errorf("Rejections() = %+v, want %+v", got, s.Rejections)
	}
	if r.Source() != sourceID {
		t.Errorf("Source() = %v, want %v", r.Source(), sourceID)
	}
}

func TestReconcileErrorsChangeNoAsset(t *testing.T) {
	base := validParams()
	record := func(id string) inventory.Record {
		return inventory.Record{RecordID: id, Imported: mustImported(t, base)}
	}
	rejection := func(id string) inventory.Rejection { return inventory.Rejection{RecordID: id, Reason: "invalid"} }
	otherSource := inventory.CMDBSourceID(uuid.New())

	tests := []struct {
		name     string
		existing []*inventory.Asset
		snapshot inventory.Snapshot
		want     error
	}{
		{"blank record id", nil, inventory.Snapshot{Records: []inventory.Record{record(" ")}}, inventory.ErrInvalidSnapshot},
		{"duplicate record", nil, inventory.Snapshot{Records: []inventory.Record{record("1"), record("1")}}, inventory.ErrInvalidSnapshot},
		{"imported and rejected", nil, inventory.Snapshot{Records: []inventory.Record{record("1")}, Rejections: []inventory.Rejection{rejection("1")}}, inventory.ErrInvalidSnapshot},
		{"blank rejection id", nil, inventory.Snapshot{Rejections: []inventory.Rejection{rejection("")}}, inventory.ErrInvalidSnapshot},
		{"duplicate rejection", nil, inventory.Snapshot{Rejections: []inventory.Rejection{rejection("1"), rejection("1")}}, inventory.ErrInvalidSnapshot},
		{"zero imported asset", nil, inventory.Snapshot{Records: []inventory.Record{{RecordID: "1"}}}, inventory.ErrZeroImportedAsset},
		{"existing asset of another source", []*inventory.Asset{assetOf(t, otherSource, "1")}, inventory.Snapshot{}, inventory.ErrInvalidExistingAssets},
		{"duplicate existing asset", []*inventory.Asset{assetOf(t, sourceID, "1"), assetOf(t, sourceID, "1")}, inventory.Snapshot{}, inventory.ErrInvalidExistingAssets},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Missing from every snapshot above, so it would be deactivated on success.
			bystander := assetOf(t, sourceID, "bystander")
			_, err := inventory.Reconcile(sourceID, append(tt.existing, bystander), tt.snapshot)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if !bystander.Active() {
				t.Error("an Asset was changed by a failed Reconcile")
			}
		})
	}
}

func with(p inventory.ImportedAssetParams, mutate func(*inventory.ImportedAssetParams)) inventory.ImportedAssetParams {
	mutate(&p)
	return p
}

func recs(id string, p inventory.ImportedAssetParams) map[string]inventory.ImportedAssetParams {
	return map[string]inventory.ImportedAssetParams{id: p}
}

func snapshot(t *testing.T, records map[string]inventory.ImportedAssetParams, rejected ...string) inventory.Snapshot {
	t.Helper()
	var s inventory.Snapshot
	for id, p := range records {
		s.Records = append(s.Records, inventory.Record{RecordID: id, Imported: mustImported(t, p)})
	}
	for _, id := range rejected {
		s.Rejections = append(s.Rejections, inventory.Rejection{RecordID: id, Reason: "invalid " + id})
	}
	return s
}

func storedAssets(t *testing.T, specs []stored) []*inventory.Asset {
	t.Helper()
	assets := make([]*inventory.Asset, len(specs))
	for i, s := range specs {
		a, err := inventory.RestoreAsset(inventory.SourceReference{Source: sourceID, RecordID: s.id}, mustImported(t, s.params), inventory.AssetState{Active: s.active})
		if err != nil {
			t.Fatal(err)
		}
		assets[i] = a
	}
	return assets
}

func assetOf(t *testing.T, source inventory.CMDBSourceID, id string) *inventory.Asset {
	t.Helper()
	a, err := inventory.NewAsset(inventory.SourceReference{Source: source, RecordID: id}, mustImported(t, validParams()))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
