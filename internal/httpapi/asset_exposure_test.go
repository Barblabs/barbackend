package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"barbackend/internal/tenancy"
	"github.com/TcM1911/stix2"
	"github.com/google/uuid"
)

var nginx = inventory.SoftwareComponent{Role: inventory.Application, Name: "nginx", Version: "1.18.0", Product: inventory.Product{Vendor: "f5", Name: "nginx"}}

// virtualMachine is a record of a Virtual Machine running nginx; iTop gives
// a Virtual Machine no Location, so its Exposure is Unknown (ADR 0021).
func virtualMachine(t *testing.T, id string, retired bool) inventory.Record {
	t.Helper()
	return inventory.Record{RecordID: id, Imported: imported(t, inventory.ImportedAssetParams{
		Name: "vm-" + id, Kind: inventory.VirtualMachine, Software: []inventory.SoftwareComponent{nginx}, Retired: retired,
	})}
}

// openFinding stores a Finding of a CVE on the record's nginx, scored as the
// Findings pipeline would score it with its Exposure Unknown.
func (e env) openFinding(t *testing.T, src inventory.CMDBSourceID, recordID string) finding.ID {
	t.Helper()
	ctx := context.Background()
	v, err := stix2.NewVulnerability("CVE-2021-23017")
	if err != nil {
		t.Fatal(err)
	}
	object, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	key, err := finding.NewKey(inventory.SourceReference{Source: src, RecordID: recordID}, nginx.Product, "CVE-2021-23017")
	if err != nil {
		t.Fatal(err)
	}
	var id finding.ID
	if err := e.db.InTx(ctx, func(tx *postgres.Tx) error {
		if err := tx.StoreVulnerability(ctx, postgres.StoredVulnerability{CVE: "CVE-2021-23017", Object: object, Modified: time.Now()}); err != nil {
			return err
		}
		if id, _, err = tx.SaveMatch(ctx, finding.Match{Key: key, Component: nginx}); err != nil {
			return err
		}
		score, err := scoring.Model1.Compute(finding.ScoreInputs(v, inventory.CriticalityUnknown, inventory.ExposureUnknown, false))
		if err != nil {
			return err
		}
		_, err = tx.SaveScoreIfChanged(ctx, id, score)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// latestExposure is the exposure multiplier of the Finding's newest Score,
// whether it has the exposure_undeclared Data Gap, and how many Scores it has.
func (e env) latestExposure(t *testing.T, id finding.ID) (multiplier float64, undeclared bool, scores int) {
	t.Helper()
	if err := e.conn.QueryRow(context.Background(), `
		SELECT s.exposure_multiplier,
		       EXISTS (SELECT 1 FROM finding_score_data_gaps g JOIN score_data_gaps d ON d.id = g.gap_id
		               WHERE g.finding_id = s.finding_id AND g.scored_at = s.scored_at AND d.name = 'exposure_undeclared'),
		       (SELECT count(*) FROM finding_scores a WHERE a.finding_id = s.finding_id)
		FROM finding_scores s WHERE s.finding_id = $1 ORDER BY s.scored_at DESC LIMIT 1`, uuid.UUID(id)).Scan(&multiplier, &undeclared, &scores); err != nil {
		t.Fatal(err)
	}
	return multiplier, undeclared, scores
}

func exposurePath(id int64) string { return fmt.Sprintf("/assets/%d/exposure", id) }

func TestDeclaringAVirtualMachineInternalRescoresItsFindingsUntilCleared(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{virtualMachine(t, "vm", false)}}
	src := e.connect(t, e.customer)
	f := e.openFinding(t, src, "vm")
	adminID, admin := e.customerAdmin(t, e.customer)
	adminEmail := e.userEmail(t, adminID)
	vm := e.assetNamed(t, "vm").ID

	declared := decode[asset](t, e.asUser(admin, http.MethodPut, exposurePath(vm), map[string]string{"exposure": "internal"}), http.StatusOK)

	if x := declared.Exposure; x.Value == nil || *x.Value != "internal" || x.Source != "declared" || x.Imported != nil ||
		x.DeclaredBy == nil || *x.DeclaredBy != adminEmail || x.DeclaredAt == nil {
		t.Errorf("declared exposure = %+v, want internal declared by %s over an Unknown import", x, adminEmail)
	}
	if m, undeclared, scores := e.latestExposure(t, f); m != 0.6 || undeclared || scores != 2 {
		t.Errorf("after declaring: multiplier %v, exposure_undeclared %v, %d scores; want 0.6 without the gap in a new score", m, undeclared, scores)
	}

	e.syncRecords(t, virtualMachine(t, "vm", false))
	if after := e.assetNamed(t, "vm").Exposure; !reflect.DeepEqual(after, declared.Exposure) {
		t.Errorf("exposure after a Sync = %+v, want the Declaration kept %+v", after, declared.Exposure)
	}

	cleared := decode[asset](t, e.asUser(admin, http.MethodDelete, exposurePath(vm), nil), http.StatusOK)

	if cleared.Exposure != (assetExposure{Source: "imported"}) {
		t.Errorf("cleared exposure = %+v, want the imported Unknown", cleared.Exposure)
	}
	if m, undeclared, scores := e.latestExposure(t, f); m != 1 || !undeclared || scores != 3 {
		t.Errorf("after clearing: multiplier %v, exposure_undeclared %v, %d scores; want 1 with the gap in a new score", m, undeclared, scores)
	}
}

func TestDeclaringExposureIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{virtualMachine(t, "vm", false), virtualMachine(t, "gone", true)}}
	e.connect(t, e.customer)
	_, admin := e.customerAdmin(t, e.customer)
	vm, gone := e.assetNamed(t, "vm").ID, e.assetNamed(t, "gone").ID
	other := e.newCustomer(t)
	e.connect(t, other)
	theirs := e.assetOf(t, "Bearer "+e.signIn(t, e.newUser(t, tenancy.Viewer, other)), "vm").ID
	tests := []struct {
		name   string
		method string
		id     int64
		body   any
		status int
		code   string
	}{
		{"unknown", http.MethodPut, vm, map[string]string{"exposure": "unknown"}, http.StatusBadRequest, "invalid_request"},
		{"an unlisted value", http.MethodPut, vm, map[string]string{"exposure": "cloud"}, http.StatusBadRequest, "invalid_request"},
		{"no value", http.MethodPut, vm, map[string]string{}, http.StatusBadRequest, "invalid_request"},
		{"an inactive asset", http.MethodPut, gone, map[string]string{"exposure": "internal"}, http.StatusConflict, "asset_inactive"},
		{"another customer's asset", http.MethodPut, theirs, map[string]string{"exposure": "internal"}, http.StatusNotFound, "asset_not_found"},
		{"clearing another customer's asset", http.MethodDelete, theirs, nil, http.StatusNotFound, "asset_not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decode[codedError](t, e.asUser(admin, tt.method, exposurePath(tt.id), tt.body), tt.status); got.Code != tt.code {
				t.Errorf("code = %q, want %q", got.Code, tt.code)
			}
		})
	}
	if x := e.assetNamed(t, "vm").Exposure; x.Source != "imported" {
		t.Errorf("exposure = %+v, want nothing declared", x)
	}
}

func TestAnExposureDeclarationOutlivesDeactivationAndIsClearedWhileInactive(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.provider.Snapshot = inventory.Snapshot{Records: []inventory.Record{virtualMachine(t, "vm", false)}}
	e.connect(t, e.customer)
	_, admin := e.customerAdmin(t, e.customer)
	vm := e.assetNamed(t, "vm").ID
	declared := decode[asset](t, e.asUser(admin, http.MethodPut, exposurePath(vm), map[string]string{"exposure": "internal"}), http.StatusOK)

	e.syncRecords(t, virtualMachine(t, "vm", true))
	if after := e.assetNamed(t, "vm"); after.Active || !reflect.DeepEqual(after.Exposure, declared.Exposure) {
		t.Errorf("after deactivation: active %v, exposure %+v; want Inactive with the Declaration kept %+v", after.Active, after.Exposure, declared.Exposure)
	}
	e.syncRecords(t, virtualMachine(t, "vm", false))
	if after := e.assetNamed(t, "vm"); !after.Active || !reflect.DeepEqual(after.Exposure, declared.Exposure) {
		t.Errorf("after reactivation: active %v, exposure %+v; want Active with the Declaration kept %+v", after.Active, after.Exposure, declared.Exposure)
	}
	e.syncRecords(t, virtualMachine(t, "vm", true))

	cleared := decode[asset](t, e.asUser(admin, http.MethodDelete, exposurePath(vm), nil), http.StatusOK)

	if cleared.Active || cleared.Exposure != (assetExposure{Source: "imported"}) {
		t.Errorf("cleared while Inactive: active %v, exposure %+v; want the imported Unknown", cleared.Active, cleared.Exposure)
	}
}
