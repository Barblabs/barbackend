package inventory_test

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"barbackend/internal/inventory"
	"github.com/google/uuid"
)

type stored struct {
	id     string
	params inventory.ImportedAssetParams
	active bool
}

type outcome struct {
	created, updated, deactivated, reactivated []string
	inactive                                   []string
}

func TestReconcile(t *testing.T) {
	osc := inventory.SoftwareComponent{Role: inventory.OperatingSystem, Name: "Ubuntu", Version: "22.04"}
	app := inventory.SoftwareComponent{Role: inventory.Application, Name: "nginx", Version: "1.24"}
	identified := app
	identified.Product = inventory.Product{Vendor: "f5", Name: "nginx"}

	base := validParams()
	renamed := with(base, func(p *inventory.ImportedAssetParams) { p.Name = "srv-01-renamed" })
	retired := with(base, func(p *inventory.ImportedAssetParams) { p.Retired = true })
	software := with(base, func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{osc, app} })
	reordered := with(base, func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{app, osc} })
	duplicated := with(base, func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{osc, app, app} })
	identifiedSoftware := with(base, func(p *inventory.ImportedAssetParams) { p.Software = []inventory.SoftwareComponent{osc, identified} })
	hardware := with(base, func(p *inventory.ImportedAssetParams) {
		p.Hardware = inventory.Hardware{Vendor: "Dell", Model: "R740"}
	})
	otherHardware := with(base, func(p *inventory.ImportedAssetParams) { p.Hardware = inventory.Hardware{Vendor: "HP", Model: "R740"} })
	exposed := with(base, func(p *inventory.ImportedAssetParams) { p.Exposure = inventory.InternetFacing })
	deployed := with(base, func(p *inventory.ImportedAssetParams) { p.Lifecycle = inventory.LifecycleProduction })

	tests := []struct {
		name     string
		existing []stored
		records  map[string]inventory.ImportedAssetParams
		skipped  []string
		want     outcome
	}{
		{"new", nil, recs("1", base), nil, outcome{created: ids("1")}},
		{"new and retired is created inactive", nil, recs("1", retired), nil, outcome{created: ids("1"), inactive: ids("1")}},
		{"changed", []stored{{"1", base, true}}, recs("1", renamed), nil, outcome{updated: ids("1")}},
		{"unchanged", []stored{{"1", base, true}}, recs("1", base), nil, outcome{}},
		{"software reordered is unchanged", []stored{{"1", software, true}}, recs("1", reordered), nil, outcome{}},
		{"duplicate software component is a change", []stored{{"1", software, true}}, recs("1", duplicated), nil, outcome{updated: ids("1")}},
		{"identified product is a change", []stored{{"1", software, true}}, recs("1", identifiedSoftware), nil, outcome{updated: ids("1")}},
		{"hardware vendor is a change", []stored{{"1", hardware, true}}, recs("1", otherHardware), nil, outcome{updated: ids("1")}},
		{"exposure is a change", []stored{{"1", base, true}}, recs("1", exposed), nil, outcome{updated: ids("1")}},
		{"lifecycle stage is a change", []stored{{"1", base, true}}, recs("1", deployed), nil, outcome{updated: ids("1")}},
		{"retired", []stored{{"1", base, true}}, recs("1", retired), nil,
			outcome{updated: ids("1"), deactivated: ids("1"), inactive: ids("1")}},
		{"missing", []stored{{"1", base, true}}, nil, nil, outcome{deactivated: ids("1"), inactive: ids("1")}},
		{"missing and already inactive", []stored{{"1", base, false}}, nil, nil, outcome{inactive: ids("1")}},
		{"reappearing", []stored{{"1", base, false}}, recs("1", base), nil, outcome{reactivated: ids("1")}},
		{"un-retired", []stored{{"1", retired, false}}, recs("1", base), nil, outcome{updated: ids("1"), reactivated: ids("1")}},
		{"retired and already inactive", []stored{{"1", retired, false}}, recs("1", retired), nil, outcome{inactive: ids("1")}},
		{"skipped but existing", []stored{{"1", base, true}}, nil, []string{"1"}, outcome{}},
		{"skipped and new", nil, nil, []string{"1"}, outcome{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existing := storedAssets(t, tt.existing)
			s := snapshot(t, tt.records, tt.skipped...)
			r, err := inventory.Reconcile(sourceID, inventory.Stored{Assets: existing}, s)
			if err != nil {
				t.Fatal(err)
			}
			all := slices.Concat(existing, r.Created())
			got := outcome{
				created:     recordIDs(r.Created()),
				updated:     recordIDs(r.Updated()),
				deactivated: recordIDs(r.Deactivated()),
				reactivated: recordIDs(r.Reactivated()),
			}
			for _, a := range all {
				if !a.Active() {
					got.inactive = append(got.inactive, a.Ref().RecordID)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("outcome = %+v, want %+v", got, tt.want)
			}
			for _, a := range all {
				if p, ok := tt.records[a.Ref().RecordID]; ok && a.Imported().Name() != p.Name {
					t.Errorf("asset %s has name %q, want the snapshot's %q", a.Ref().RecordID, a.Imported().Name(), p.Name)
				}
			}
		})
	}
}

func ids(recordIDs ...string) []string { return recordIDs }

func recordIDs(assets []*inventory.Asset) []string {
	var ids []string
	for _, a := range assets {
		ids = append(ids, a.Ref().RecordID)
	}
	return ids
}

func TestReconciliationCountsAndSkippedRecords(t *testing.T) {
	base := validParams()
	retired := with(base, func(p *inventory.ImportedAssetParams) { p.Retired = true })
	renamed := with(base, func(p *inventory.ImportedAssetParams) { p.Name = "renamed" })
	existing := storedAssets(t, []stored{
		{"changed", base, true},
		{"retired", base, true},
		{"missing", base, true},
		{"reappearing", base, false},
		{"skipped", base, true},
	})
	s := snapshot(t, map[string]inventory.ImportedAssetParams{
		"new": base, "changed": renamed, "retired": retired, "reappearing": base,
	}, "skipped", "skipped-new")

	r, err := inventory.Reconcile(sourceID, inventory.Stored{Assets: existing}, s)
	if err != nil {
		t.Fatal(err)
	}
	want := inventory.SyncCounts{Created: 1, Updated: 2, Deactivated: 2, Reactivated: 1, Skipped: 2}
	if got := r.Counts(); got != want {
		t.Errorf("Counts() = %+v, want %+v", got, want)
	}
	if got := r.Skipped(); !reflect.DeepEqual(got, s.Skipped) {
		t.Errorf("Skipped() = %+v, want %+v", got, s.Skipped)
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
	skippedRecord := func(id string) inventory.SkippedRecord {
		return inventory.SkippedRecord{RecordID: id, Reason: "invalid"}
	}
	otherSource := inventory.CMDBSourceID(uuid.New())

	tests := []struct {
		name     string
		existing []*inventory.Asset
		snapshot inventory.Snapshot
		want     error
	}{
		{"blank record id", nil, inventory.Snapshot{Records: []inventory.Record{record(" ")}}, inventory.ErrInvalidSnapshot},
		{"duplicate record", nil, inventory.Snapshot{Records: []inventory.Record{record("1"), record("1")}}, inventory.ErrInvalidSnapshot},
		{"imported and skipped", nil, inventory.Snapshot{Records: []inventory.Record{record("1")}, Skipped: []inventory.SkippedRecord{skippedRecord("1")}}, inventory.ErrInvalidSnapshot},
		{"blank skipped record id", nil, inventory.Snapshot{Skipped: []inventory.SkippedRecord{skippedRecord("")}}, inventory.ErrInvalidSnapshot},
		{"duplicate skipped record", nil, inventory.Snapshot{Skipped: []inventory.SkippedRecord{skippedRecord("1"), skippedRecord("1")}}, inventory.ErrInvalidSnapshot},
		{"zero imported asset", nil, inventory.Snapshot{Records: []inventory.Record{{RecordID: "1"}}}, inventory.ErrZeroImportedAsset},
		{"existing asset of another source", []*inventory.Asset{assetOf(t, otherSource, "1")}, inventory.Snapshot{}, inventory.ErrInvalidExistingAssets},
		{"duplicate existing asset", []*inventory.Asset{assetOf(t, sourceID, "1"), assetOf(t, sourceID, "1")}, inventory.Snapshot{}, inventory.ErrInvalidExistingAssets},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bystander := assetOf(t, sourceID, "bystander")
			_, err := inventory.Reconcile(sourceID, inventory.Stored{Assets: append(tt.existing, bystander)}, tt.snapshot)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if !bystander.Active() {
				t.Error("an Asset was changed by a failed Reconcile")
			}
		})
	}
}

func TestReconcileKeepsDeclarations(t *testing.T) {
	declared := mustOwner(t, "declared@example.com")
	first := with(validParams(), func(p *inventory.ImportedAssetParams) { p.Owner = mustOwner(t, "first@example.com") })
	second := with(first, func(p *inventory.ImportedAssetParams) { p.Owner = mustOwner(t, "second@example.com") })
	a := newAsset(t, first)
	if err := a.DeclareOwner(declared); err != nil {
		t.Fatal(err)
	}
	if err := a.DeclareExposure(inventory.InternetFacing); err != nil {
		t.Fatal(err)
	}

	r, err := inventory.Reconcile(sourceID, inventory.Stored{Assets: []*inventory.Asset{a}}, snapshot(t, recs("1", second)))
	if err != nil {
		t.Fatal(err)
	}
	if got := recordIDs(r.Updated()); !reflect.DeepEqual(got, ids("1")) {
		t.Fatalf("updated = %v, want [1]", got)
	}
	if o, _ := a.Owner(); o != declared {
		t.Errorf("Owner() = %v, want the declared owner", o)
	}
	if a.Exposure() != inventory.InternetFacing {
		t.Errorf("Exposure() = %v, want InternetFacing", a.Exposure())
	}
	a.ClearOwnerDeclaration()
	if o, _ := a.Owner(); o.String() != "second@example.com" {
		t.Errorf("Owner() after clearing = %v, want the newly imported owner", o)
	}
}

func TestReconcileRejectsZeroSource(t *testing.T) {
	_, err := inventory.Reconcile(inventory.CMDBSourceID{}, inventory.Stored{}, inventory.Snapshot{})
	if !errors.Is(err, inventory.ErrInvalidSourceReference) {
		t.Fatalf("err = %v, want ErrInvalidSourceReference", err)
	}
}

type storedArea struct {
	id, name string
	active   bool
}

type areaOutcome struct {
	created, renamed, deactivated, reactivated []string
	inactive                                   []string
}

func TestReconcileAreas(t *testing.T) {
	it := inventory.ImportedAreaParams{Name: "IT"}
	renamed := inventory.ImportedAreaParams{Name: "Information Technology"}
	inactive := inventory.ImportedAreaParams{Name: "IT", Inactive: true}

	tests := []struct {
		name     string
		existing []storedArea
		areas    map[string]inventory.ImportedAreaParams
		want     areaOutcome
	}{
		{"new", nil, areaRecs("1", it), areaOutcome{created: ids("1")}},
		{"new and inactive is created inactive", nil, areaRecs("1", inactive), areaOutcome{created: ids("1"), inactive: ids("1")}},
		{"unchanged", []storedArea{{"1", "IT", true}}, areaRecs("1", it), areaOutcome{}},
		{"renamed", []storedArea{{"1", "IT", true}}, areaRecs("1", renamed), areaOutcome{renamed: ids("1")}},
		{"missing", []storedArea{{"1", "IT", true}}, nil, areaOutcome{deactivated: ids("1"), inactive: ids("1")}},
		{"missing and already inactive", []storedArea{{"1", "IT", false}}, nil, areaOutcome{inactive: ids("1")}},
		{"marked inactive", []storedArea{{"1", "IT", true}}, areaRecs("1", inactive), areaOutcome{deactivated: ids("1"), inactive: ids("1")}},
		{"reappearing", []storedArea{{"1", "IT", false}}, areaRecs("1", it), areaOutcome{reactivated: ids("1")}},
		{"renamed and reappearing", []storedArea{{"1", "IT", false}}, areaRecs("1", renamed), areaOutcome{renamed: ids("1"), reactivated: ids("1")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner := mustOwner(t, "owner@example.com")
			var existing []*inventory.Area
			for _, sa := range tt.existing {
				existing = append(existing, restoreArea(t, sa.id, sa.name, inventory.AreaState{Active: sa.active, Owner: owner}))
			}
			var s inventory.Snapshot
			for id, p := range tt.areas {
				s.Areas = append(s.Areas, inventory.AreaRecord{RecordID: id, Imported: mustImportedArea(t, p.Name, p.Inactive)})
			}
			r, err := inventory.Reconcile(sourceID, inventory.Stored{Areas: existing}, s)
			if err != nil {
				t.Fatal(err)
			}
			changes := r.Areas()
			all := slices.Concat(existing, changes.Created)
			got := areaOutcome{
				created:     areaIDs(changes.Created),
				renamed:     areaIDs(changes.Renamed),
				deactivated: areaIDs(changes.Deactivated),
				reactivated: areaIDs(changes.Reactivated),
			}
			for _, a := range all {
				if !a.Active() {
					got.inactive = append(got.inactive, a.Ref().RecordID)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("outcome = %+v, want %+v", got, tt.want)
			}
			for _, a := range all {
				if p, ok := tt.areas[a.Ref().RecordID]; ok && a.Name() != p.Name {
					t.Errorf("area %s has name %q, want the snapshot's %q", a.Ref().RecordID, a.Name(), p.Name)
				}
			}
			for _, a := range existing {
				if o, ok := a.Owner(); !ok || o != owner {
					t.Errorf("area %s has owner %v, %v; want %v kept", a.Ref().RecordID, o, ok, owner)
				}
			}
			for _, a := range changes.Created {
				if o, ok := a.Owner(); ok {
					t.Errorf("created area %s has owner %v, want none", a.Ref().RecordID, o)
				}
			}
			if r.Counts() != (inventory.SyncCounts{}) {
				t.Errorf("Counts() = %+v, want no Asset counted", r.Counts())
			}
		})
	}
}

func TestReconcileAssetArea(t *testing.T) {
	inIT := with(validParams(), func(p *inventory.ImportedAssetParams) { p.Area = "it" })
	inSales := with(validParams(), func(p *inventory.ImportedAssetParams) { p.Area = "sales" })
	tests := []struct {
		name     string
		existing inventory.ImportedAssetParams
		imported inventory.ImportedAssetParams
		want     []string
	}{
		{"same area", inIT, inIT, nil},
		{"area changed", inIT, inSales, ids("1")},
		{"area set", validParams(), inIT, ids("1")},
		{"area cleared", inIT, validParams(), ids("1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existing := storedAssets(t, []stored{{"1", tt.existing, true}})
			s := snapshot(t, recs("1", tt.imported))
			s.Areas = []inventory.AreaRecord{
				{RecordID: "it", Imported: mustImportedArea(t, "IT", false)},
				{RecordID: "sales", Imported: mustImportedArea(t, "Sales", false)},
			}
			r, err := inventory.Reconcile(sourceID, inventory.Stored{Assets: existing}, s)
			if err != nil {
				t.Fatal(err)
			}
			if got := recordIDs(r.Updated()); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("updated = %v, want %v", got, tt.want)
			}
			if got, _ := existing[0].Imported().Area(); got != tt.imported.Area {
				t.Errorf("Area() = %q, want %q", got, tt.imported.Area)
			}
		})
	}
}

func TestReconcileAreaErrorsChangeNothing(t *testing.T) {
	area := func(id string) inventory.AreaRecord {
		return inventory.AreaRecord{RecordID: id, Imported: mustImportedArea(t, "IT", false)}
	}
	inArea := func(id, area string) inventory.Record {
		return inventory.Record{RecordID: id, Imported: mustImported(t, with(validParams(), func(p *inventory.ImportedAssetParams) { p.Area = area }))}
	}
	otherSource := inventory.CMDBSourceID(uuid.New())
	otherArea, err := inventory.RestoreArea(inventory.SourceReference{Source: otherSource, RecordID: "1"}, "IT", inventory.AreaState{Active: true})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		existing []*inventory.Area
		snapshot inventory.Snapshot
		want     error
	}{
		{"blank area id", nil, inventory.Snapshot{Areas: []inventory.AreaRecord{area(" ")}}, inventory.ErrInvalidSnapshot},
		{"duplicate area", nil, inventory.Snapshot{Areas: []inventory.AreaRecord{area("1"), area("1")}}, inventory.ErrInvalidSnapshot},
		{"zero imported area", nil, inventory.Snapshot{Areas: []inventory.AreaRecord{{RecordID: "1"}}}, inventory.ErrZeroImportedArea},
		{"unknown area", nil, inventory.Snapshot{Areas: []inventory.AreaRecord{area("1")}, Records: []inventory.Record{inArea("a", "2")}}, inventory.ErrInvalidSnapshot},
		{"existing area of another source", []*inventory.Area{otherArea}, inventory.Snapshot{}, inventory.ErrInvalidExistingAreas},
		{"duplicate existing area", []*inventory.Area{
			restoreArea(t, "1", "IT", inventory.AreaState{Active: true}),
			restoreArea(t, "1", "IT", inventory.AreaState{Active: true}),
		}, inventory.Snapshot{}, inventory.ErrInvalidExistingAreas},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bystanderArea := restoreArea(t, "bystander", "IT", inventory.AreaState{Active: true})
			bystander := assetOf(t, sourceID, "bystander")
			existing := inventory.Stored{Assets: []*inventory.Asset{bystander}, Areas: append(tt.existing, bystanderArea)}
			_, err := inventory.Reconcile(sourceID, existing, tt.snapshot)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if !bystander.Active() || !bystanderArea.Active() {
				t.Error("an Asset or Area was changed by a failed Reconcile")
			}
		})
	}
}

func areaRecs(id string, p inventory.ImportedAreaParams) map[string]inventory.ImportedAreaParams {
	return map[string]inventory.ImportedAreaParams{id: p}
}

func areaIDs(areas []*inventory.Area) []string {
	var ids []string
	for _, a := range areas {
		ids = append(ids, a.Ref().RecordID)
	}
	return ids
}

func with(p inventory.ImportedAssetParams, mutate func(*inventory.ImportedAssetParams)) inventory.ImportedAssetParams {
	mutate(&p)
	return p
}

func recs(id string, p inventory.ImportedAssetParams) map[string]inventory.ImportedAssetParams {
	return map[string]inventory.ImportedAssetParams{id: p}
}

func snapshot(t *testing.T, records map[string]inventory.ImportedAssetParams, skipped ...string) inventory.Snapshot {
	t.Helper()
	var s inventory.Snapshot
	for id, p := range records {
		s.Records = append(s.Records, inventory.Record{RecordID: id, Imported: mustImported(t, p)})
	}
	for _, id := range skipped {
		s.Skipped = append(s.Skipped, inventory.SkippedRecord{RecordID: id, Reason: "invalid " + id})
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
