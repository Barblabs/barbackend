package advisories_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"barbackend/internal/advisories"
	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

var march = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

func inTx(t *testing.T, db *postgres.DB, fn func(*postgres.Tx) error) {
	t.Helper()
	if err := db.InTx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

// storeVulnerability stores cve as a Vulnerability that opened a Finding.
func storeVulnerability(t *testing.T, db *postgres.DB, cve string) {
	t.Helper()
	object := json.RawMessage(fmt.Sprintf(`{"type":"vulnerability","id":%q,"name":%q}`, stixext.VulnerabilityID(cve), cve))
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.StoreVulnerability(context.Background(), postgres.StoredVulnerability{CVE: cve, Object: object, Modified: march})
	})
}

// bulletin is an AWS Security Bulletin as the AWS adapter emits it: its
// description is text, and its object_refs are the Vulnerabilities of refs.
func bulletin(t *testing.T, guid, text string, refs ...string) *stix2.Report {
	t.Helper()
	objects := make([]stix2.Identifier, len(refs))
	for i, cve := range refs {
		objects[i] = stixext.VulnerabilityID(cve)
	}
	r, err := stix2.NewReport(guid, &stix2.Timestamp{Time: march}, objects, stix2.OptionDescription(text))
	if err != nil {
		t.Fatal(err)
	}
	r.ID = stixext.ID(stix2.TypeReport, guid)
	return r
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

func handle(t *testing.T, db *postgres.DB, batch ...stix2.STIXObject) {
	t.Helper()
	if err := advisories.New(db).HandleAWS(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
}

func TestHandleAWSLinksABulletinToTheStoredVulnerabilitiesItNames(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	storeVulnerability(t, db, "CVE-2026-0001")
	r := bulletin(t, "AWS-2026-001", "Fixes CVE-2026-0001 and CVE-2026-0002.", "CVE-2026-0001", "CVE-2026-0002")

	handle(t, db, r)

	got := advisoriesOf(t, db, "CVE-2026-0001")
	if len(got) != 1 || got[0].ID != string(r.ID) || got[0].Feed != "aws" || !got[0].Published.Equal(march) {
		t.Fatalf("advisories of CVE-2026-0001 = %+v, want the bulletin from aws published %s", got, march)
	}
}

func TestHandleAWSDiscardsABulletinThatNamesNoStoredVulnerability(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	storeVulnerability(t, db, "CVE-2026-0001")
	kept := bulletin(t, "AWS-2026-001", "Fixes CVE-2026-0001.", "CVE-2026-0001")
	discarded := bulletin(t, "AWS-2026-002", "Fixes CVE-2026-0003.", "CVE-2026-0003")

	handle(t, db, discarded, kept)

	var count int
	inTx(t, db, func(tx *postgres.Tx) error {
		for _, cve := range []string{"CVE-2026-0001", "CVE-2026-0003"} {
			a, err := tx.AdvisoriesOf(context.Background(), cve)
			if err != nil {
				return err
			}
			count += len(a)
		}
		return nil
	})
	if count != 1 {
		t.Errorf("%d advisories linked, want only the bulletin that names a stored CVE", count)
	}
}

func TestHandleAWSIgnoresACVEOnlyItsTextMentions(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	storeVulnerability(t, db, "CVE-2026-0001")
	storeVulnerability(t, db, "CVE-2026-0002")
	r := bulletin(t, "AWS-2026-001", "Fixes CVE-2026-0001; see also CVE-2026-0002.", "CVE-2026-0001")

	handle(t, db, r)

	if got := advisoriesOf(t, db, "CVE-2026-0002"); len(got) != 0 {
		t.Errorf("advisories of CVE-2026-0002 = %+v, want none: the bulletin does not refer to it", got)
	}
}

func TestHandleAWSPublishedAgainAddsLinksAndKeepsTheOldOnes(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	storeVulnerability(t, db, "CVE-2026-0001")
	storeVulnerability(t, db, "CVE-2026-0002")
	handle(t, db, bulletin(t, "AWS-2026-001", "Fixes CVE-2026-0001.", "CVE-2026-0001"))

	handle(t, db, bulletin(t, "AWS-2026-001", "Fixes CVE-2026-0002.", "CVE-2026-0002"))

	for _, cve := range []string{"CVE-2026-0001", "CVE-2026-0002"} {
		if got := advisoriesOf(t, db, cve); len(got) != 1 {
			t.Errorf("advisories of %s = %+v, want the bulletin: links are added, never removed", cve, got)
		}
	}
}
