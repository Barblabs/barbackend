package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/postgres/pgtest"
)

const (
	t1190ID = "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c"
	t1100ID = "attack-pattern--c16e5409-ee53-4d79-afdc-4099dc9292df"
	m1051ID = "course-of-action--e5d930e9-775a-40ad-9bdb-b941d8dfe86b"
	m1016ID = "course-of-action--15437c6d-b998-4a36-be41-4ace3d54d266"
)

var may = time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)

func technique(id, attackID, name string, modified time.Time) postgres.AttackTechnique {
	return postgres.AttackTechnique{
		ID: id, AttackID: attackID, Name: name, Tactics: []string{"initial-access"},
		Object: json.RawMessage(`{"type":"attack-pattern"}`), Modified: modified,
	}
}

func mitigation(id, attackID, name string) postgres.AttackMitigation {
	return postgres.AttackMitigation{ID: id, AttackID: attackID, Name: name, Object: json.RawMessage(`{"type":"course-of-action"}`), Modified: may}
}

func relationship(id, typ, source, target, description string) postgres.AttackRelationship {
	return postgres.AttackRelationship{ID: id, Type: typ, Source: source, Target: target, Description: description, Modified: may}
}

func readTechnique(t *testing.T, db *postgres.DB, attackID string) postgres.AttackTechnique {
	t.Helper()
	var out postgres.AttackTechnique
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		out, err = tx.AttackTechnique(context.Background(), attackID)
		return err
	})
	return out
}

func TestAttackTechniqueIsReadByItsATTACKID(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	inTx(t, db, func(tx *postgres.Tx) error {
		return tx.StoreAttackTechnique(context.Background(), technique(t1190ID, "T1190", "Exploit Public-Facing Application", may))
	})

	got := readTechnique(t, db, "T1190")
	if got.ID != t1190ID || got.Name != "Exploit Public-Facing Application" || len(got.Tactics) != 1 || got.Tactics[0] != "initial-access" {
		t.Errorf("T1190 = %+v, want the stored Technique", got)
	}
	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.AttackTechnique(context.Background(), "T9999")
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("unknown Technique err = %v, want ErrNotFound", err)
	}
}

func TestStoreAttackTechniqueReplacesItOnlyWithALaterModification(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	store := func(name string, modified time.Time) {
		inTx(t, db, func(tx *postgres.Tx) error {
			return tx.StoreAttackTechnique(context.Background(), technique(t1190ID, "T1190", name, modified))
		})
	}
	store("current", may)

	store("older", may.AddDate(0, -1, 0))
	if got := readTechnique(t, db, "T1190").Name; got != "current" {
		t.Errorf("name = %q after an older version, want it kept", got)
	}
	store("newer", may.AddDate(0, 1, 0))
	if got := readTechnique(t, db, "T1190").Name; got != "newer" {
		t.Errorf("name = %q after a newer version, want it replaced", got)
	}
}

func TestMitigationsOfATechniqueComeWithTheirAdvice(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	inTx(t, db, func(tx *postgres.Tx) error {
		ctx := context.Background()
		// The relationships arrive before the objects they join, as a batch
		// of the Feed can hand them over.
		for _, r := range []postgres.AttackRelationship{
			relationship("relationship--0005fb3b-274a-4ac1-8fb2-51366fcd1a6b", "mitigates", m1051ID, t1190ID, "Update software regularly."),
			relationship("relationship--1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "mitigates", m1016ID, t1190ID, "Scan for vulnerabilities."),
			relationship("relationship--2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e", "mitigates", m1051ID, t1100ID, "Not for T1190."),
		} {
			if err := tx.StoreAttackRelationship(ctx, r); err != nil {
				return err
			}
		}
		for _, m := range []postgres.AttackMitigation{mitigation(m1051ID, "M1051", "Update Software"), mitigation(m1016ID, "M1016", "Vulnerability Scanning")} {
			if err := tx.StoreAttackMitigation(ctx, m); err != nil {
				return err
			}
		}
		return nil
	})

	var got []postgres.TechniqueMitigation
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		got, err = tx.MitigationsOf(context.Background(), t1190ID)
		return err
	})
	want := []postgres.TechniqueMitigation{
		{AttackID: "M1016", Name: "Vulnerability Scanning", Advice: "Scan for vulnerabilities."},
		{AttackID: "M1051", Name: "Update Software", Advice: "Update software regularly."},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("mitigations of T1190 = %+v, want %+v", got, want)
	}
}

func TestRevokingTechniqueIsTheOneThatReplacedIt(t *testing.T) {
	t.Parallel()
	db := pgtest.NewDB(t)
	inTx(t, db, func(tx *postgres.Tx) error {
		ctx := context.Background()
		revoked := technique(t1100ID, "T1100", "Web Shell", may)
		revoked.Revoked = true
		if err := tx.StoreAttackTechnique(ctx, revoked); err != nil {
			return err
		}
		if err := tx.StoreAttackTechnique(ctx, technique(t1190ID, "T1190", "Exploit Public-Facing Application", may)); err != nil {
			return err
		}
		return tx.StoreAttackRelationship(ctx, relationship("relationship--3c4d5e6f-7a8b-4c9d-8e1f-2a3b4c5d6e7f", "revoked-by", t1100ID, t1190ID, ""))
	})

	var got postgres.AttackTechnique
	inTx(t, db, func(tx *postgres.Tx) (err error) {
		got, err = tx.RevokingTechnique(context.Background(), t1100ID)
		return err
	})
	if got.AttackID != "T1190" {
		t.Errorf("technique replacing T1100 = %s, want T1190", got.AttackID)
	}
	err := db.InTx(context.Background(), func(tx *postgres.Tx) error {
		_, err := tx.RevokingTechnique(context.Background(), t1190ID)
		return err
	})
	if !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("technique replacing a current one err = %v, want ErrNotFound", err)
	}
}
