package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/stixext"
)

var (
	nvdKey  = string(stixext.NVDDefinitionID)
	epssKey = string(stixext.EPSSDefinitionID)
	kevKey  = string(stixext.KEVDefinitionID)
)

// vulnerabilityObject is a STIX vulnerability whose nvd/1 extension lists
// affected as given, raw JSON, and has that status.
func vulnerabilityObject(cve, status, affected string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"type":"vulnerability","name":%q,"extensions":{%q:{"vuln_status":%q,"affected":%s}}}`,
		cve, nvdKey, status, affected))
}

func storeVulnerability(t *testing.T, db *postgres.DB, cve string, modified time.Time, object json.RawMessage) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.StoreVulnerability(context.Background(), postgres.StoredVulnerability{CVE: cve, Object: object, Modified: modified})
	})
}

func storedExtensions(t *testing.T, db *postgres.DB, cve string) map[string]map[string]any {
	t.Helper()
	var v postgres.StoredVulnerability
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		v, err = tx.Vulnerability(context.Background(), cve)
		return err
	})
	var object struct {
		Extensions map[string]map[string]any `json:"extensions"`
	}
	if err := json.Unmarshal(v.Object, &object); err != nil {
		t.Fatal(err)
	}
	return object.Extensions
}

func setExtension(t *testing.T, db *postgres.DB, cve, key, extension string) bool {
	t.Helper()
	var stored bool
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		stored, err = tx.SetVulnerabilityExtension(context.Background(), cve, key, json.RawMessage(extension))
		return err
	})
	return stored
}

func TestStoreVulnerabilityKeepsTheExtensionsOfOtherFeeds(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	march := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	storeVulnerability(t, db, "CVE-2021-23017", march, vulnerabilityObject("CVE-2021-23017", "Analyzed", `[]`))
	if !setExtension(t, db, "CVE-2021-23017", epssKey, `{"probability":0.42}`) {
		t.Fatal("epss/1 not set on a stored CVE")
	}
	storeVulnerability(t, db, "CVE-2021-23017", march.AddDate(0, 0, 1), vulnerabilityObject("CVE-2021-23017", "Modified", `[]`))

	ext := storedExtensions(t, db, "CVE-2021-23017")
	if ext[nvdKey]["vuln_status"] != "Modified" {
		t.Errorf("nvd/1 = %v, want the newer NVD data", ext[nvdKey])
	}
	if ext[epssKey]["probability"] != 0.42 {
		t.Errorf("epss/1 = %v, want it kept", ext[epssKey])
	}
}

func TestStoreVulnerabilityIgnoresAnOlderModification(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	march := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	storeVulnerability(t, db, "CVE-2021-23017", march, vulnerabilityObject("CVE-2021-23017", "Modified", `[]`))
	storeVulnerability(t, db, "CVE-2021-23017", march.AddDate(0, 0, -1), vulnerabilityObject("CVE-2021-23017", "Analyzed", `[]`))

	if got := storedExtensions(t, db, "CVE-2021-23017")[nvdKey]["vuln_status"]; got != "Modified" {
		t.Errorf("vuln_status = %v, want the newer Modified kept", got)
	}
}

func TestSetVulnerabilityExtensionReplacesOnlyItsOwnKey(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	storeVulnerability(t, db, "CVE-2021-44228", time.Now(), vulnerabilityObject("CVE-2021-44228", "Analyzed", `[]`))
	setExtension(t, db, "CVE-2021-44228", kevKey, `{"date_added":"2021-12-10"}`)
	setExtension(t, db, "CVE-2021-44228", epssKey, `{"probability":0.5}`)
	setExtension(t, db, "CVE-2021-44228", epssKey, `{"probability":0.97}`)

	ext := storedExtensions(t, db, "CVE-2021-44228")
	if ext[epssKey]["probability"] != 0.97 || ext[kevKey]["date_added"] != "2021-12-10" || ext[nvdKey] == nil {
		t.Errorf("extensions = %v, want the latest EPSS next to KEV and NVD", ext)
	}
}

func TestSetVulnerabilityExtensionIgnoresAnUnstoredCVE(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	if setExtension(t, db, "CVE-2099-0001", epssKey, `{"probability":0.1}`) {
		t.Error("extension set on a CVE that is not stored")
	}
}

func TestStoredCVEsNamesOnlyTheStoredOnes(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	storeVulnerability(t, db, "CVE-2021-23017", time.Now(), vulnerabilityObject("CVE-2021-23017", "Analyzed", `[]`))
	storeVulnerability(t, db, "CVE-2024-3094", time.Now(), vulnerabilityObject("CVE-2024-3094", "Analyzed", `[]`))
	var stored []string
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		stored, err = tx.StoredCVEs(context.Background(), []string{"CVE-2099-0001", "CVE-2024-3094", "CVE-2021-23017"})
		return err
	})
	if !slices.Equal(stored, []string{"CVE-2021-23017", "CVE-2024-3094"}) {
		t.Errorf("stored = %v, want the two stored CVEs in order", stored)
	}
}

func TestVulnerabilityOfAnUnstoredCVEIsNotFound(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.Vulnerability(context.Background(), "CVE-2099-0001")
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestVulnerabilitiesAffectingMatchesProductsIgnoringCase(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	now := time.Now()
	storeVulnerability(t, db, "CVE-2021-23017", now, vulnerabilityObject("CVE-2021-23017", "Analyzed", `[{"vendor":"f5","product":"nginx"}]`))
	storeVulnerability(t, db, "CVE-2024-3094", now, vulnerabilityObject("CVE-2024-3094", "Analyzed", `[{"vendor":"tukaani","product":"xz"}]`))
	storeVulnerability(t, db, "CVE-2025-0001", now, vulnerabilityObject("CVE-2025-0001", "Awaiting Analysis", `null`))

	var got []postgres.StoredVulnerability
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		got, err = tx.VulnerabilitiesAffecting(context.Background(), nvdKey, []inventory.Product{{Vendor: "F5", Name: " NGINX "}})
		return err
	})
	if len(got) != 1 || got[0].CVE != "CVE-2021-23017" {
		t.Errorf("vulnerabilities = %+v, want only CVE-2021-23017", got)
	}
}
