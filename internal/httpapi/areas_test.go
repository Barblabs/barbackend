package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"barbackend/internal/inventory"
)

type areaList struct {
	Areas []area `json:"areas"`
}

type area struct {
	ID            int64   `json:"id"`
	SourceID      string  `json:"source_id"`
	RecordID      string  `json:"record_id"`
	Name          string  `json:"name"`
	OwnerEmail    *string `json:"owner_email"`
	Active        bool    `json:"active"`
	InactiveSince *string `json:"inactive_since"`
}

func (e env) listAreas(query url.Values) *httptest.ResponseRecorder {
	return e.do(httptest.NewRequest(http.MethodGet, "/areas?"+query.Encode(), nil))
}

func TestListAreasShape(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Areas: []inventory.AreaRecord{areaRecord(t, "1", "IT"), areaRecord(t, "2", "Sales")}}
	src := e.connect(t, e.customer)
	if _, err := e.conn.Exec(context.Background(), "UPDATE customer_areas SET owner_email = 'owner@example.com' WHERE record_id = '1'"); err != nil {
		t.Fatal(err)
	}

	page := decode[areaList](t, e.listAreas(url.Values{}), http.StatusOK)

	if len(page.Areas) != 2 {
		t.Fatalf("areas = %+v, want two", page.Areas)
	}
	it, sales := page.Areas[0], page.Areas[1]
	if it.ID != e.areaID(t, "1") || it.SourceID != src.String() || it.RecordID != "1" || it.Name != "IT" ||
		it.OwnerEmail == nil || *it.OwnerEmail != "owner@example.com" || !it.Active || it.InactiveSince != nil {
		t.Errorf("IT = %+v", it)
	}
	if sales.Name != "Sales" || sales.OwnerEmail != nil {
		t.Errorf("Sales = %+v, want a null owner_email", sales)
	}
}

func TestListAreasFiltersByActive(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Areas: []inventory.AreaRecord{areaRecord(t, "1", "IT"), areaRecord(t, "2", "Old")}}
	e.connect(t, e.customer)
	e.provider.Snapshot = inventory.Snapshot{Areas: []inventory.AreaRecord{areaRecord(t, "1", "IT")}}
	if rec := e.sync(context.Background()); rec.Code != http.StatusOK {
		t.Fatalf("sync = %d %s", rec.Code, rec.Body)
	}

	tests := []struct {
		active string
		want   string
	}{
		{"", "[IT]"},
		{"true", "[IT]"},
		{"false", "[Old]"},
		{"all", "[IT Old]"},
	}
	for _, tt := range tests {
		t.Run("active="+tt.active, func(t *testing.T) {
			query := url.Values{}
			if tt.active != "" {
				query.Set("active", tt.active)
			}
			page := decode[areaList](t, e.listAreas(query), http.StatusOK)
			var got []string
			for _, a := range page.Areas {
				got = append(got, a.Name)
			}
			if fmt.Sprint(got) != tt.want {
				t.Errorf("areas = %v, want %s", got, tt.want)
			}
		})
	}
}

func TestListAreasRejectsABadActive(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	got := decode[codedError](t, e.listAreas(url.Values{"active": {"maybe"}}), http.StatusBadRequest)

	if got.Code != "invalid_request" {
		t.Errorf("code = %q, want invalid_request", got.Code)
	}
}

func TestListAreasWithoutAreasIsEmpty(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	rec := e.listAreas(url.Values{})

	if rec.Code != http.StatusOK || rec.Body.String() != `{"areas":[]}` {
		t.Errorf("response = %d %s, want an empty list", rec.Code, rec.Body)
	}
}

func (e env) setAreaOwner(authorization string, id int64, email any) *httptest.ResponseRecorder {
	return e.asUser(authorization, http.MethodPut, "/areas/"+strconv.FormatInt(id, 10)+"/owner", map[string]any{"email": email})
}

func TestCustomerAdminSetsAndClearsAnAreasOwner(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Areas: []inventory.AreaRecord{areaRecord(t, "1", "IT")}}
	e.connect(t, e.customer)
	_, admin := e.customerAdmin(t, e.customer)
	id := e.areaID(t, "1")

	set := decode[area](t, e.setAreaOwner(admin, id, "Ana@Example.com"), http.StatusOK)
	if set.ID != id || set.Name != "IT" || set.OwnerEmail == nil || *set.OwnerEmail != "ana@example.com" {
		t.Errorf("after setting = %+v, want IT owned by ana@example.com", set)
	}

	cleared := decode[area](t, e.setAreaOwner(admin, id, nil), http.StatusOK)
	if cleared.OwnerEmail != nil {
		t.Errorf("owner_email after clearing = %q, want null", *cleared.OwnerEmail)
	}
}

func TestSetAreaOwnerRejectsABadEmail(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Areas: []inventory.AreaRecord{areaRecord(t, "1", "IT")}}
	e.connect(t, e.customer)
	_, admin := e.customerAdmin(t, e.customer)

	got := decode[codedError](t, e.setAreaOwner(admin, e.areaID(t, "1"), "not an email"), http.StatusBadRequest)

	if got.Code != "invalid_request" {
		t.Errorf("code = %q, want invalid_request", got.Code)
	}
}

func TestSetOwnerOfAnotherCustomersAreaIsNotFound(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	other := e.newCustomer(t)
	e.provider.Snapshot = inventory.Snapshot{Areas: []inventory.AreaRecord{areaRecord(t, "1", "Theirs")}}
	e.connect(t, other)
	var theirs int64
	if err := e.conn.QueryRow(context.Background(), "SELECT id FROM customer_areas").Scan(&theirs); err != nil {
		t.Fatal(err)
	}
	_, admin := e.customerAdmin(t, e.customer)

	got := decode[codedError](t, e.setAreaOwner(admin, theirs, "ana@example.com"), http.StatusNotFound)

	if got.Code != "area_not_found" {
		t.Errorf("code = %q, want area_not_found", got.Code)
	}
}
