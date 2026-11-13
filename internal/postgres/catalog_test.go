package postgres_test

import (
	"context"
	"fmt"
	"maps"
	"testing"

	"barbackend/internal/assessment"
	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/matching"
	"barbackend/internal/postgres/pgtest"
	"barbackend/internal/scoring"
	"barbackend/internal/tenancy"
	"github.com/jackc/pgx/v5"
)

func TestCatalogsMatchDomainConstants(t *testing.T) {
	t.Parallel()
	catalogs := map[string]map[int16]string{
		"asset_kinds":           names(inventory.Server, inventory.VirtualMachine, inventory.Workstation, inventory.NetworkDevice),
		"criticalities":         names(inventory.CriticalityHigh, inventory.CriticalityMedium, inventory.CriticalityLow),
		"exposures":             names(inventory.InternetFacing, inventory.Internal),
		"lifecycle_stages":      names(inventory.LifecycleProduction, inventory.LifecycleImplementation, inventory.LifecycleStock),
		"software_roles":        names(inventory.OperatingSystem, inventory.Application),
		"sync_outcomes":         names(inventory.SyncSucceeded, inventory.SyncFailed),
		"user_roles":            names(tenancy.PlatformAdmin, tenancy.CustomerAdmin, tenancy.Viewer),
		"feedback_verdicts":     names(assessment.VerdictApplies, assessment.VerdictDoesNotApply, assessment.VerdictRemediated, assessment.VerdictShouldBeEarlier, assessment.VerdictShouldBeLater),
		"match_flags":           names(matching.VersionUnparsed, matching.DistroBackport),
		"finding_close_reasons": names(finding.NoLongerAffected, finding.ComponentRemoved, finding.AssetInactive, finding.VulnerabilityRejected),
		"score_data_gaps":       names(scoring.CVSSEstimated, scoring.EPSSPending, scoring.KEVStale, scoring.CriticalityUnknown, scoring.ExposureUndeclared, scoring.LifecycleUnknown),
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
