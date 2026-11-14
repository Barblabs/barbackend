package httpapi_test

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/tenancy"
)

type assetInformationClassification struct {
	Value      *string    `json:"value"`
	DeclaredBy *string    `json:"declared_by"`
	DeclaredAt *time.Time `json:"declared_at"`
}

func informationClassificationPath(id int64) string {
	return fmt.Sprintf("/assets/%d/information-classification", id)
}

func informationClassificationBody(value string) map[string]string {
	return map[string]string{"information_classification": value}
}

func TestDeclaringAnInformationClassificationKeepsItThroughASync(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{virtualMachine(t, "vm", false)}}
	e.connect(t, e.customer)
	adminID, admin := e.customerAdmin(t, e.customer)
	adminEmail := e.userEmail(t, adminID)
	vm := e.assetNamed(t, "vm")
	if vm.InformationClassification != (assetInformationClassification{}) {
		t.Fatalf("classification before declaring = %+v, want Unclassified", vm.InformationClassification)
	}

	declared := decode[asset](t, e.asUser(admin, http.MethodPut, informationClassificationPath(vm.ID), informationClassificationBody("confidential")), http.StatusOK)

	if c := declared.InformationClassification; c.Value == nil || *c.Value != "confidential" ||
		c.DeclaredBy == nil || *c.DeclaredBy != adminEmail || c.DeclaredAt == nil {
		t.Errorf("declared classification = %+v, want confidential declared by %s", c, adminEmail)
	}

	e.syncRecords(t, virtualMachine(t, "vm", false))
	if after := e.assetNamed(t, "vm").InformationClassification; !reflect.DeepEqual(after, declared.InformationClassification) {
		t.Errorf("classification after a Sync = %+v, want the Declaration kept %+v", after, declared.InformationClassification)
	}

	cleared := decode[asset](t, e.asUser(admin, http.MethodDelete, informationClassificationPath(vm.ID), nil), http.StatusOK)

	if cleared.InformationClassification != (assetInformationClassification{}) {
		t.Errorf("cleared classification = %+v, want Unclassified", cleared.InformationClassification)
	}
}

func TestDeclaringAnInformationClassificationIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{virtualMachine(t, "vm", false), virtualMachine(t, "gone", true)}}
	e.connect(t, e.customer)
	_, admin := e.customerAdmin(t, e.customer)
	viewer := "Bearer " + e.signIn(t, e.newUser(t, tenancy.Viewer, e.customer))
	vm, gone := e.assetNamed(t, "vm").ID, e.assetNamed(t, "gone").ID
	other := e.newCustomer(t)
	e.connect(t, other)
	theirs := e.assetOf(t, "Bearer "+e.signIn(t, e.newUser(t, tenancy.Viewer, other)), "vm").ID
	tests := []struct {
		name   string
		caller string
		method string
		id     int64
		body   any
		status int
		code   string
	}{
		{"a viewer declaring", viewer, http.MethodPut, vm, informationClassificationBody("private"), http.StatusForbidden, "forbidden"},
		{"a viewer clearing", viewer, http.MethodDelete, vm, nil, http.StatusForbidden, "forbidden"},
		{"unclassified", admin, http.MethodPut, vm, informationClassificationBody("unclassified"), http.StatusBadRequest, "invalid_request"},
		{"an unlisted value", admin, http.MethodPut, vm, informationClassificationBody("internal"), http.StatusBadRequest, "invalid_request"},
		{"no value", admin, http.MethodPut, vm, map[string]string{}, http.StatusBadRequest, "invalid_request"},
		{"an inactive asset", admin, http.MethodPut, gone, informationClassificationBody("private"), http.StatusConflict, "asset_inactive"},
		{"another customer's asset", admin, http.MethodPut, theirs, informationClassificationBody("private"), http.StatusNotFound, "asset_not_found"},
		{"clearing another customer's asset", admin, http.MethodDelete, theirs, nil, http.StatusNotFound, "asset_not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decode[codedError](t, e.asUser(tt.caller, tt.method, informationClassificationPath(tt.id), tt.body), tt.status); got.Code != tt.code {
				t.Errorf("code = %q, want %q", got.Code, tt.code)
			}
		})
	}
	if c := e.assetNamed(t, "vm").InformationClassification; c != (assetInformationClassification{}) {
		t.Errorf("classification = %+v, want nothing declared", c)
	}
}

func TestAnInformationClassificationIsClearedWhileInactive(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{virtualMachine(t, "vm", false)}}
	e.connect(t, e.customer)
	_, admin := e.customerAdmin(t, e.customer)
	vm := e.assetNamed(t, "vm").ID
	declared := decode[asset](t, e.asUser(admin, http.MethodPut, informationClassificationPath(vm), informationClassificationBody("public")), http.StatusOK)

	e.syncRecords(t, virtualMachine(t, "vm", true))
	if after := e.assetNamed(t, "vm"); after.Active || !reflect.DeepEqual(after.InformationClassification, declared.InformationClassification) {
		t.Errorf("after deactivation: active %v, classification %+v; want Inactive with the Declaration kept %+v",
			after.Active, after.InformationClassification, declared.InformationClassification)
	}

	cleared := decode[asset](t, e.asUser(admin, http.MethodDelete, informationClassificationPath(vm), nil), http.StatusOK)

	if cleared.Active || cleared.InformationClassification != (assetInformationClassification{}) {
		t.Errorf("cleared while Inactive: active %v, classification %+v; want Unclassified", cleared.Active, cleared.InformationClassification)
	}
}
