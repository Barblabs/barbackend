package findings_test

import (
	"context"
	"slices"
	"testing"

	"barbackend/internal/inventory"
)

func (w world) afterSync(t *testing.T, records ...inventory.Record) {
	t.Helper()
	w.sync(t, records...)
	if err := w.findings.AfterSync(context.Background(), w.source); err != nil {
		t.Fatal(err)
	}
}

func TestAfterSyncMatchesANewAssetAgainstStoredVulnerabilities(t *testing.T) {
	t.Parallel()
	w, _ := matchedPayments(t)

	w.afterSync(t,
		server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")),
		server(t, "web-02", inventory.CriticalityMedium, app("Nginx of web-02", "f5", "nginx", "1.19.0")),
	)

	f, ok := w.finding(t, "web-02", "CVE-2021-23017")
	if !ok || !f.open || f.version != "1.19.0" {
		t.Fatalf("web-02 finding = %+v (%t), want it opened against the CVE already stored", f, ok)
	}
	if _, _, _, scores := w.latestScore(t, f.id); scores != 1 {
		t.Errorf("web-02 scores = %d, want it scored", scores)
	}
}

// exposedTo is the record with that imported Exposure, as a Location in the
// CMDB gives it (ADR 0021).
func exposedTo(t *testing.T, r inventory.Record, e inventory.Exposure) inventory.Record {
	t.Helper()
	p := inventory.ImportedAssetParams{
		Name: r.Imported.Name(), Kind: r.Imported.Kind(), Software: r.Imported.Software(),
		Criticality: r.Imported.Criticality(), Exposure: e,
	}
	imported, err := inventory.NewImportedAsset(p)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.Record{RecordID: r.RecordID, Imported: imported}
}

// inStage is the record with that Lifecycle Stage, as the iTop status gives
// it (ADR 0028).
func inStage(t *testing.T, r inventory.Record, s inventory.LifecycleStage) inventory.Record {
	t.Helper()
	p := inventory.ImportedAssetParams{
		Name: r.Imported.Name(), Kind: r.Imported.Kind(), Software: r.Imported.Software(),
		Criticality: r.Imported.Criticality(), Exposure: r.Imported.Exposure(), Lifecycle: s,
	}
	imported, err := inventory.NewImportedAsset(p)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.Record{RecordID: r.RecordID, Imported: imported}
}

func TestAfterSyncRescoresWhenTheLifecycleStageChanges(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	payments := server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0"))
	multiplier := func() (m float64, scores int) {
		t.Helper()
		_, _, _, scores = w.latestScore(t, f.id)
		return w.latestLifecycleMultiplier(t, f.id), scores
	}

	w.afterSync(t, inStage(t, payments, inventory.LifecycleStock))
	if m, scores := multiplier(); m != 0.3 || scores != 2 {
		t.Errorf("in stock: multiplier %v in %d scores, want 0.3 in a second score", m, scores)
	}
	if _, _, gaps, _ := w.latestScore(t, f.id); slices.Contains(gaps, "lifecycle_unknown") {
		t.Errorf("gaps = %v, want no lifecycle_unknown once the CMDB gives the stage", gaps)
	}

	w.afterSync(t, inStage(t, payments, inventory.LifecycleProduction))
	if m, scores := multiplier(); m != 1 || scores != 3 {
		t.Errorf("deployed to production: multiplier %v in %d scores, want 1 in a third score", m, scores)
	}
}

func TestAfterSyncRescoresWhenTheExposureChanges(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	payments := server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0"))
	multiplier := func() (m float64, scores int) {
		t.Helper()
		_, _, _, scores = w.latestScore(t, f.id)
		return w.latestExposureMultiplier(t, f.id), scores
	}

	w.afterSync(t, exposedTo(t, payments, inventory.Internal))
	if m, scores := multiplier(); m != 0.6 || scores != 2 {
		t.Errorf("after the CMDB made it Internal: multiplier %v in %d scores, want 0.6 in a second score", m, scores)
	}
	if _, _, gaps, _ := w.latestScore(t, f.id); slices.Contains(gaps, "exposure_undeclared") {
		t.Errorf("gaps = %v, want no exposure_undeclared once the CMDB gives the Exposure", gaps)
	}

	w.declareExposure(t, "payments", inventory.InternetFacing)
	w.afterSync(t, exposedTo(t, payments, inventory.Internal))
	if m, scores := multiplier(); m != 1 || scores != 3 {
		t.Errorf("after declaring it Internet-facing: multiplier %v in %d scores, want the Declaration's 1 in a third score", m, scores)
	}
}

func TestAfterSyncClosesWhatNoLongerMatchesWithItsReason(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.sync(t,
		server(t, "upgraded", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")),
		server(t, "uninstalled", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")),
		server(t, "retired", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")),
		server(t, "patched-later", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")),
	)
	w.handleNVD(t, nvdVulnerability(t, "CVE-2021-23017", "Analyzed", nginxBefore1201))

	w.afterSync(t,
		server(t, "upgraded", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.20.1")),
		server(t, "uninstalled", inventory.CriticalityHigh, app("Apache", "apache", "http_server", "2.4.57")),
		server(t, "patched-later", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.19.0")),
	)

	for record, want := range map[string]string{
		"upgraded":    "no_longer_affected",
		"uninstalled": "component_removed",
		"retired":     "asset_inactive",
	} {
		if f := w.mustFinding(t, record, "CVE-2021-23017"); f.open || f.closeReason != want {
			t.Errorf("%s finding = %+v, want closed %s", record, f, want)
		}
	}
	if f := w.mustFinding(t, "patched-later", "CVE-2021-23017"); !f.open || f.version != "1.19.0" {
		t.Errorf("patched-later finding = %+v, want open at the still vulnerable 1.19.0", f)
	}
}

func TestAfterSyncReopensTheSameFindingWhenItMatchesAgain(t *testing.T) {
	t.Parallel()
	w, before := matchedPayments(t)
	w.afterSync(t, server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.20.1")))

	w.afterSync(t, server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0")))

	after := w.mustFinding(t, "payments", "CVE-2021-23017")
	if !after.open || after.id != before.id || after.closeReason != "" {
		t.Errorf("finding = %+v, want %v reopened", after, before.id)
	}
}

func TestAfterSyncRescoresWhenTheAssetsCriticalityChanges(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)

	w.afterSync(t, server(t, "payments", inventory.CriticalityLow, app("Nginx", "f5", "nginx", "1.18.0")))

	if _, _, _, scores := w.latestScore(t, f.id); scores != 2 {
		t.Errorf("scores = %d, want a new Score for the lower Criticality", scores)
	}
}
