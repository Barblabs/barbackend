package postgres_test

import (
	"context"
	"fmt"
	"maps"
	"testing"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/pgtest"
	"github.com/jackc/pgx/v5"
)

// Catalog ids are the Go constants (ADR 0006); this catches either side drifting.
func TestCatalogsMatchDomainConstants(t *testing.T) {
	t.Parallel()
	catalogs := map[string]map[int16]string{
		"asset_kinds":    names(inventory.Server, inventory.VirtualMachine, inventory.Workstation, inventory.NetworkDevice),
		"criticalities":  names(inventory.CriticalityHigh, inventory.CriticalityMedium, inventory.CriticalityLow),
		"exposures":      names(inventory.InternetFacing, inventory.Internal),
		"software_roles": names(inventory.OperatingSystem, inventory.Application),
	}
	ctx := context.Background()
	conn := pgtest.Conn(t, pgtest.URL(t))

	for table, want := range catalogs {
		t.Run(table, func(t *testing.T) {
			rows, _ := conn.Query(ctx, "SELECT id, name FROM "+table)
			got := map[int16]string{}
			var id int16
			var name string
			_, err := pgx.ForEachRow(rows, []any{&id, &name}, func() error {
				got[id] = name
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(got, want) {
				t.Errorf("rows = %v, want %v", got, want)
			}
		})
	}
}

func names[T interface {
	~int
	fmt.Stringer
}](values ...T) map[int16]string {
	m := make(map[int16]string, len(values))
	for _, v := range values {
		m[int16(v)] = v.String()
	}
	return m
}
