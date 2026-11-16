package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"barbackend/internal/inventory"
)

func TestFindingsSummaryOfACustomerWithoutFindingsIsAnEmptyList(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	got := decode[struct {
		Assets *[]struct{} `json:"assets"`
	}](t, e.do(httptest.NewRequest(http.MethodGet, "/assets/findings-summary", nil)), http.StatusOK)

	if got.Assets == nil || len(*got.Assets) != 0 {
		t.Errorf("assets = %v, want an empty list, not null", got.Assets)
	}
}

type assetList struct {
	Assets     []asset `json:"assets"`
	NextCursor *string `json:"next_cursor"`
	Total      int     `json:"total"`
}

type asset struct {
	ID       int64                           `json:"id"`
	SourceID string                          `json:"source_id"`
	RecordID string                          `json:"record_id"`
	Name     string                          `json:"name"`
	Kind     string                          `json:"kind"`
	Hardware *struct{ Vendor, Model string } `json:"hardware"`
	Software []struct {
		Role    string                         `json:"role"`
		Name    string                         `json:"name"`
		Version string                         `json:"version"`
		Product *struct{ Vendor, Name string } `json:"product"`
	} `json:"software"`
	Criticality               *string                         `json:"criticality"`
	Exposure                  assetExposure                   `json:"exposure"`
	Lifecycle                 *string                         `json:"lifecycle_stage"`
	InformationClassification assetInformationClassification  `json:"information_classification"`
	Owner                     *struct{ Email, Source string } `json:"owner"`
	Area                      *areaRef                        `json:"area"`
	Retired                   bool                            `json:"retired"`
	Active                    bool                            `json:"active"`
	InactiveSince             *string                         `json:"inactive_since"`
}

type assetExposure struct {
	Value      *string    `json:"value"`
	Source     string     `json:"source"`
	Imported   *string    `json:"imported"`
	DeclaredBy *string    `json:"declared_by"`
	DeclaredAt *time.Time `json:"declared_at"`
}

type areaRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func (e env) listAssets(query url.Values) *httptest.ResponseRecorder {
	return e.do(httptest.NewRequest(http.MethodGet, "/assets?"+query.Encode(), nil))
}

func (e env) syncRecords(t *testing.T, records ...inventory.Record) {
	t.Helper()
	e.provider.Snapshot = inventory.Snapshot{Records: records}
	if rec := e.sync(context.Background()); rec.Code != http.StatusOK {
		t.Fatalf("sync = %d %s", rec.Code, rec.Body)
	}
}

func TestListAssetsPagesEveryAssetOnceInSortOrder(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{
		record(t, "5", "b"), record(t, "2", "a"), record(t, "4", "b"), record(t, "1", "a"), record(t, "3", "c"),
	}}
	e.connect(t, e.customer)

	var got []string
	query := url.Values{"limit": {"2"}}
	for pages := 0; ; pages++ {
		page := decode[assetList](t, e.listAssets(query), http.StatusOK)
		if page.Total != 5 {
			t.Fatalf("total = %d, want 5", page.Total)
		}
		for _, a := range page.Assets {
			got = append(got, a.Name+a.RecordID)
		}
		if page.NextCursor == nil {
			if len(page.Assets) != 1 {
				t.Errorf("last page has %d assets, want 1", len(page.Assets))
			}
			break
		}
		if pages > 5 {
			t.Fatal("paging does not end")
		}
		query.Set("cursor", *page.NextCursor)
	}

	want := []string{"a1", "a2", "b4", "b5", "c3"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("paged assets = %v, want %v", got, want)
	}
}

func TestListAssetsSurvivesADeactivationBetweenPages(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "1", "a"), record(t, "2", "b"), record(t, "3", "c"), record(t, "4", "d")}}
	e.connect(t, e.customer)
	first := decode[assetList](t, e.listAssets(url.Values{"limit": {"2"}}), http.StatusOK)

	e.syncRecords(t, record(t, "1", "a"), record(t, "3", "c"), record(t, "4", "d"))
	second := decode[assetList](t, e.listAssets(url.Values{"limit": {"2"}, "cursor": {*first.NextCursor}}), http.StatusOK)

	if len(second.Assets) != 2 || second.Assets[0].RecordID != "3" || second.Assets[1].RecordID != "4" {
		t.Errorf("second page = %+v, want records 3 and 4", second.Assets)
	}
}

func TestListAssetsFilters(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	asset := func(id, name string, k inventory.AssetKind, c inventory.Criticality, x inventory.Exposure, l inventory.LifecycleStage, area string) inventory.Record {
		return inventory.Record{RecordID: id, Imported: imported(t, inventory.ImportedAssetParams{Name: name, Kind: k, Criticality: c, Exposure: x, Lifecycle: l, Area: area})}
	}
	active := []inventory.Record{
		asset("1", "a", inventory.Server, inventory.CriticalityHigh, inventory.InternetFacing, inventory.LifecycleProduction, "it"),
		asset("2", "b", inventory.Server, inventory.CriticalityLow, inventory.Internal, inventory.LifecycleImplementation, "it"),
		record(t, "3", "c"),
		asset("5", "e", inventory.Workstation, inventory.CriticalityMedium, inventory.Internal, inventory.LifecycleStock, ""),
	}
	areas := []inventory.AreaRecord{areaRecord(t, "it", "IT")}
	snapshot := func(records ...inventory.Record) inventory.Snapshot {
		return inventory.Snapshot{Areas: areas, Records: records}
	}
	e.provider.Snapshot = snapshot(append(active, record(t, "4", "d"))...)
	e.connect(t, e.customer)
	e.provider.Snapshot = snapshot(active...)
	if rec := e.sync(context.Background()); rec.Code != http.StatusOK {
		t.Fatalf("sync = %d %s", rec.Code, rec.Body)
	}
	_, admin := e.customerAdmin(t, e.customer)
	if rec := e.asUser(admin, http.MethodPut, informationClassificationPath(e.assetNamed(t, "1").ID), informationClassificationBody("confidential")); rec.Code != http.StatusOK {
		t.Fatalf("declare classification = %d %s", rec.Code, rec.Body)
	}
	it := strconv.FormatInt(e.areaID(t, "it"), 10)

	tests := []struct {
		name  string
		query url.Values
		want  []string
	}{
		{"default hides inactive", url.Values{}, []string{"1", "2", "3", "5"}},
		{"active false", url.Values{"active": {"false"}}, []string{"4"}},
		{"active all", url.Values{"active": {"all"}}, []string{"1", "2", "3", "4", "5"}},
		{"kind", url.Values{"kind": {"server"}}, []string{"1", "2"}},
		{"kinds", url.Values{"kind": {"server", "workstation"}}, []string{"1", "2", "5"}},
		{"criticality", url.Values{"criticality": {"high"}}, []string{"1"}},
		{"unknown criticality", url.Values{"criticality": {"unknown"}}, []string{"3"}},
		{"unknown exposure", url.Values{"exposure": {"unknown"}}, []string{"3"}},
		{"confidential", url.Values{"information_classification": {"confidential"}}, []string{"1"}},
		{"unclassified", url.Values{"information_classification": {"unclassified"}}, []string{"2", "3", "5"}},
		{"lifecycle stage", url.Values{"lifecycle_stage": {"production"}}, []string{"1"}},
		{"lifecycle stages", url.Values{"lifecycle_stage": {"implementation", "stock"}}, []string{"2", "5"}},
		{"unknown lifecycle stage", url.Values{"lifecycle_stage": {"unknown"}}, []string{"3"}},
		{"lifecycle stage and kind", url.Values{"lifecycle_stage": {"implementation", "stock"}, "kind": {"server"}}, []string{"2"}},
		{"area", url.Values{"area": {it}}, []string{"1", "2"}},
		{"classification and area", url.Values{"information_classification": {"confidential"}, "area": {it}}, []string{"1"}},
		{"kind and inactive", url.Values{"kind": {"virtual_machine"}, "active": {"all"}}, []string{"3", "4"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := decode[assetList](t, e.listAssets(tt.query), http.StatusOK)
			var got []string
			for _, a := range page.Assets {
				got = append(got, a.RecordID)
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) || page.Total != len(tt.want) {
				t.Errorf("records = %v total %d, want %v", got, page.Total, tt.want)
			}
		})
	}
}

func TestListAssetsIncludesAssetsOfDisconnectedSourcesOnlyWhenInactiveAllowed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "1", "old")}}
	e.connect(t, e.customer)
	if rec := e.do(httptest.NewRequest(http.MethodDelete, "/cmdb/source", nil)); rec.Code != http.StatusNoContent {
		t.Fatalf("disconnect = %d %s", rec.Code, rec.Body)
	}
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "1", "new")}}
	e.connect(t, e.customer)

	active := decode[assetList](t, e.listAssets(url.Values{}), http.StatusOK)
	all := decode[assetList](t, e.listAssets(url.Values{"active": {"all"}}), http.StatusOK)
	inactive := decode[assetList](t, e.listAssets(url.Values{"active": {"false"}}), http.StatusOK)

	if len(active.Assets) != 1 || active.Assets[0].Name != "new" {
		t.Errorf("default = %+v, want only new", active.Assets)
	}
	if len(all.Assets) != 2 || len(inactive.Assets) != 1 || inactive.Assets[0].Name != "old" || inactive.Assets[0].InactiveSince == nil || inactive.Assets[0].Active {
		t.Errorf("all = %d assets, inactive = %+v, want the disconnected one inactive", len(all.Assets), inactive.Assets)
	}
}

func TestListAssetsOnlyReturnsTheCustomersAssets(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "1", "mine")}}
	e.connect(t, e.customer)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "1", "theirs")}}
	e.connect(t, e.newCustomer(t))

	page := decode[assetList](t, e.listAssets(url.Values{"active": {"all"}}), http.StatusOK)

	if len(page.Assets) != 1 || page.Assets[0].Name != "mine" || page.Total != 1 {
		t.Errorf("assets = %+v total %d, want only mine", page.Assets, page.Total)
	}
}

func TestListAssetsWithoutAssetsIsEmpty(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	rec := e.listAssets(url.Values{})

	if rec.Code != http.StatusOK || rec.Body.String() != `{"assets":[],"next_cursor":null,"total":0}` {
		t.Errorf("response = %d %s, want an empty list", rec.Code, rec.Body)
	}
}

func TestListAssetsShape(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	owner, _ := inventory.NewOwnerEmail("imported@example.com")
	physical := imported(t, inventory.ImportedAssetParams{
		Name: "phys", Kind: inventory.Server, Criticality: inventory.CriticalityHigh, Exposure: inventory.InternetFacing, Owner: owner, Area: "7",
		Lifecycle: inventory.LifecycleStock, Hardware: inventory.Hardware{Vendor: "Dell", Model: "R640"},
		Software: []inventory.SoftwareComponent{
			{Role: inventory.OperatingSystem, Name: "Ubuntu", Version: "22.04", Product: inventory.Product{Vendor: "Canonical", Name: "Ubuntu"}},
			{Role: inventory.Application, Name: "mystery", Version: "1"},
		},
	})
	e.provider.Snapshot = inventory.Snapshot{
		Areas:   []inventory.AreaRecord{areaRecord(t, "7", "IT")},
		Records: []inventory.Record{{RecordID: "P", Imported: physical}, record(t, "V", "virt")},
	}
	e.connect(t, e.customer)
	if _, err := e.conn.Exec(context.Background(), `
		WITH owner AS (INSERT INTO asset_owners (customer_id, email) VALUES ($1, 'declared@example.com') RETURNING id)
		UPDATE assets SET declared_owner_id = (SELECT id FROM owner) WHERE record_id = 'P'`, [16]byte(e.customer)); err != nil {
		t.Fatal(err)
	}

	page := decode[assetList](t, e.listAssets(url.Values{}), http.StatusOK)

	phys, virt := page.Assets[0], page.Assets[1]
	if phys.RecordID != "P" {
		phys, virt = virt, phys
	}
	if phys.ID == 0 || phys.ID == virt.ID || phys.Kind != "server" || phys.Hardware == nil || *phys.Criticality != "high" || !phys.Active || phys.InactiveSince != nil {
		t.Errorf("physical = %+v", phys)
	}
	if phys.Owner == nil || *phys.Owner != (struct{ Email, Source string }{"declared@example.com", "declared"}) {
		t.Errorf("owner = %+v, want the declared one", phys.Owner)
	}
	if x := phys.Exposure; x.Value == nil || *x.Value != "internet_facing" || x.Source != "imported" || x.Imported == nil || *x.Imported != "internet_facing" || x.DeclaredBy != nil || x.DeclaredAt != nil {
		t.Errorf("exposure = %+v, want the imported internet_facing", x)
	}
	if phys.Lifecycle == nil || *phys.Lifecycle != "stock" || virt.Lifecycle != nil {
		t.Errorf("lifecycle stages = %v, %v, want stock and null for Unknown", phys.Lifecycle, virt.Lifecycle)
	}
	if phys.Area == nil || phys.Area.Name != "IT" || phys.Area.ID != e.areaID(t, "7") {
		t.Errorf("area = %+v, want IT", phys.Area)
	}
	if len(phys.Software) != 2 || phys.Software[0].Role != "operating_system" || phys.Software[0].Product == nil || phys.Software[1].Product != nil {
		t.Errorf("software = %+v, want an identified OS then an unidentified application", phys.Software)
	}
	if virt.Hardware != nil || virt.Owner != nil || virt.Area != nil || virt.Criticality != nil || virt.Software == nil || len(virt.Software) != 0 {
		t.Errorf("virtual = %+v, want null hardware, owner, area and criticality and an empty software array", virt)
	}
	if virt.Exposure != (assetExposure{Source: "imported"}) {
		t.Errorf("virtual exposure = %+v, want an imported Unknown: null value and imported", virt.Exposure)
	}
}

func TestListAssetsRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "1", "a"), record(t, "2", "b")}}
	e.connect(t, e.customer)
	page := decode[assetList](t, e.listAssets(url.Values{"limit": {"1"}}), http.StatusOK)

	tests := []struct {
		name  string
		query url.Values
	}{
		{"limit zero", url.Values{"limit": {"0"}}},
		{"limit too large", url.Values{"limit": {"201"}}},
		{"limit not a number", url.Values{"limit": {"many"}}},
		{"unknown kind", url.Values{"kind": {"toaster"}}},
		{"unknown criticality", url.Values{"criticality": {"vital"}}},
		{"one unknown kind among several", url.Values{"kind": {"server", "toaster"}}},
		{"unlisted exposure", url.Values{"exposure": {"cloud"}}},
		{"unlisted lifecycle stage", url.Values{"lifecycle_stage": {"obsolete"}}},
		{"retired as lifecycle stage", url.Values{"lifecycle_stage": {"retired"}}},
		{"bad active", url.Values{"active": {"maybe"}}},
		{"malformed cursor", url.Values{"cursor": {"not-a-cursor"}}},
		{"cursor with other filters", url.Values{"cursor": {*page.NextCursor}, "kind": {"server"}}},
		{"cursor with other active", url.Values{"cursor": {*page.NextCursor}, "active": {"all"}}},
		{"cursor with other exposure", url.Values{"cursor": {*page.NextCursor}, "exposure": {"unknown"}}},
		{"cursor with other lifecycle stage", url.Values{"cursor": {*page.NextCursor}, "lifecycle_stage": {"unknown"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decode[codedError](t, e.listAssets(tt.query), http.StatusBadRequest)
			if got.Code != "invalid_request" {
				t.Errorf("code = %q, want invalid_request", got.Code)
			}
		})
	}
}

func TestListAssetsCursorTakesTheSameFilterValuesInAnyOrder(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{record(t, "1", "a"), record(t, "2", "b")}}
	e.connect(t, e.customer)
	first := decode[assetList](t, e.listAssets(url.Values{"limit": {"1"}, "kind": {"virtual_machine", "server"}}), http.StatusOK)

	reordered := url.Values{"limit": {"1"}, "cursor": {*first.NextCursor}, "kind": {"server", "virtual_machine", "server"}}
	second := decode[assetList](t, e.listAssets(reordered), http.StatusOK)
	if len(second.Assets) != 1 || second.Assets[0].RecordID != "2" {
		t.Errorf("second page = %+v, want record 2", second.Assets)
	}

	other := url.Values{"limit": {"1"}, "cursor": {*first.NextCursor}, "kind": {"virtual_machine"}}
	if got := decode[codedError](t, e.listAssets(other), http.StatusBadRequest); got.Code != "invalid_request" {
		t.Errorf("cursor with other values: code = %q, want invalid_request", got.Code)
	}
}

func TestListAssetsAcceptsTheLimitBounds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, limit := range []string{"1", "200"} {
		if rec := e.listAssets(url.Values{"limit": {limit}}); rec.Code != http.StatusOK {
			t.Errorf("limit %s = %d %s, want 200", limit, rec.Code, rec.Body)
		}
	}
}
