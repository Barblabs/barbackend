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

func TestAfterSyncRescoresWhenTheExposureChanges(t *testing.T) {
	t.Parallel()
	w, f := matchedPayments(t)
	payments := server(t, "payments", inventory.CriticalityHigh, app("Nginx", "f5", "nginx", "1.18.0"))
	multiplier := func() (m float64, scores int) {
		t.Helper()
		if err := w.conn.QueryRow(context.Background(), `
			SELECT exposure_multiplier, (SELECT count(*) FROM finding_scores WHERE finding_id = $1)
			FROM finding_scores WHERE finding_id = $1 ORDER BY scored_at DESC LIMIT 1`, f.id).Scan(&m, &scores); err != nil {
			t.Fatal(err)
		}
		return m, scores
	}

	w.afterSync(t, exposedTo(t, payments, inventory.Internal))
	if m, scores := multiplier(); m != 0.6 || scores != 2 {
		t.Errorf("after the CMDB made it Internal: multiplier %v in %d scores, want 0.6 in a second score", m, scores)
	}
	if _, _, gaps, _ := w.latestScore(t, f.id); slices.Contains(gaps, "exposure_undeclared") {
		t.Errorf("gaps = %v, want no exposure_undeclared once the CMDB gives the Exposure", gaps)
	}

	w.exec(t, `
		WITH admin AS (
			INSERT INTO users (id, cognito_sub, email, customer_id, role_id)
			SELECT gen_random_uuid(), gen_random_uuid()::text, 'admin@example.com', s.customer_id, 2
			FROM cmdb_sources s JOIN assets a ON a.cmdb_source_id = s.id WHERE a.record_id = 'payments'
			RETURNING id
		)
		UPDATE assets
		SET declared_exposure_id = $1, exposure_declared_by = (SELECT id FROM admin), exposure_declared_at = now()
		WHERE record_id = 'payments'`, int16(inventory.InternetFacing))
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
