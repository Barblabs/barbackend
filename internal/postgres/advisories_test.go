package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
)

const advisoryID = "report--5a2b7c1e-3f4d-5e6f-8a9b-0c1d2e3f4a5b"

func advisory(name string, modified time.Time) postgres.StoredAdvisory {
	return postgres.StoredAdvisory{
		ID:        advisoryID,
		Feed:      "aws",
		Published: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		Object:    json.RawMessage(fmt.Sprintf(`{"type":"report","id":%q,"name":%q}`, advisoryID, name)),
		Modified:  modified,
	}
}

func storeAdvisory(t *testing.T, db *postgres.DB, a postgres.StoredAdvisory, cves ...string) {
	t.Helper()
	inTx(t, db, func(tx *postgres.Tx) error { return tx.StoreAdvisory(context.Background(), a, cves) })
}

func advisoriesOf(t *testing.T, db *postgres.DB, cve string) []postgres.StoredAdvisory {
	t.Helper()
	var out []postgres.StoredAdvisory
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		out, err = tx.AdvisoriesOf(context.Background(), cve)
		return err
	})
	return out
}

func objectName(t *testing.T, a postgres.StoredAdvisory) string {
	t.Helper()
	var object struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(a.Object, &object); err != nil {
		t.Fatal(err)
	}
	return object.Name
}

func TestStoreAdvisoryLinksItToTheVulnerabilitiesItNames(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	march := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	storeVulnerability(t, db, "CVE-2026-0001", march, vulnerabilityObject("CVE-2026-0001", "Analyzed", `[]`))
	storeVulnerability(t, db, "CVE-2026-0002", march, vulnerabilityObject("CVE-2026-0002", "Analyzed", `[]`))

	storeAdvisory(t, db, advisory("AWS-2026-001", march), "CVE-2026-0001")

	got := advisoriesOf(t, db, "CVE-2026-0001")
	if len(got) != 1 || got[0].ID != advisoryID || got[0].Feed != "aws" {
		t.Fatalf("advisories of CVE-2026-0001 = %+v, want the stored one", got)
	}
	if other := advisoriesOf(t, db, "CVE-2026-0002"); len(other) != 0 {
		t.Errorf("advisories of CVE-2026-0002 = %+v, want none: the Advisory does not name it", other)
	}
}

func TestStoreAdvisoryAgainReplacesItAndKeepsItsLinks(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	march := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	storeVulnerability(t, db, "CVE-2026-0001", march, vulnerabilityObject("CVE-2026-0001", "Analyzed", `[]`))
	storeVulnerability(t, db, "CVE-2026-0002", march, vulnerabilityObject("CVE-2026-0002", "Analyzed", `[]`))
	storeAdvisory(t, db, advisory("AWS-2026-001", march), "CVE-2026-0001")

	storeAdvisory(t, db, advisory("AWS-2026-001 (updated)", march.AddDate(0, 0, 1)), "CVE-2026-0002")

	for _, cve := range []string{"CVE-2026-0001", "CVE-2026-0002"} {
		got := advisoriesOf(t, db, cve)
		if len(got) != 1 {
			t.Fatalf("advisories of %s = %+v, want the one Advisory: links are added, never removed", cve, got)
		}
		if name := objectName(t, got[0]); name != "AWS-2026-001 (updated)" {
			t.Errorf("advisory of %s is named %q, want the object published again", cve, name)
		}
	}
}

func TestStoreAdvisoryRefusesAVulnerabilityNotStored(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		return tx.StoreAdvisory(context.Background(), advisory("AWS-2026-001", time.Now()), []string{"CVE-2026-9999"})
	})
	if err == nil {
		t.Fatal("stored an Advisory linked to a CVE that is not stored")
	}
}
