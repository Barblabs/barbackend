package finding_test

import (
	"errors"
	"testing"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/matching"
	"barbackend/internal/stixext"
	"github.com/google/uuid"
)

var server = inventory.SourceReference{Source: inventory.CMDBSourceID(uuid.New()), RecordID: "32"}

func TestNewKeyStoresTheProductInLowerCase(t *testing.T) {
	t.Parallel()
	key, err := finding.NewKey(server, inventory.Product{Vendor: " HashiCorp ", Name: "Vault"}, " cve-2024-2048 ")
	if err != nil {
		t.Fatal(err)
	}
	want := finding.Key{Asset: server, Vendor: "hashicorp", Product: "vault", CVE: "CVE-2024-2048"}
	if key != want {
		t.Errorf("key = %+v, want %+v", key, want)
	}
}

func TestNewKeyRejectsIncompleteKeys(t *testing.T) {
	t.Parallel()
	vault := inventory.Product{Vendor: "hashicorp", Name: "vault"}
	tests := []struct {
		name    string
		asset   inventory.SourceReference
		product inventory.Product
		cve     string
		want    error
	}{
		{"no asset", inventory.SourceReference{}, vault, "CVE-2024-2048", finding.ErrInvalidAsset},
		{"not a CVE", server, vault, "GHSA-xxxx-yyyy", finding.ErrInvalidCVE},
		{"no product", server, inventory.Product{}, "CVE-2024-2048", finding.ErrNoProduct},
		{"blank vendor", server, inventory.Product{Vendor: " ", Name: "vault"}, "CVE-2024-2048", finding.ErrNoProduct},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := finding.NewKey(tt.asset, tt.product, tt.cve); !errors.Is(err, tt.want) {
				t.Errorf("NewKey error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNewMatchKeepsTheEvidenceAndFlags(t *testing.T) {
	t.Parallel()
	c := inventory.SoftwareComponent{Role: inventory.Application, Name: "Nginx of payments", Version: "1.18.0", Product: inventory.Product{Vendor: "F5", Name: "nginx"}}
	entry := stixext.Affected{Vendor: "f5", Product: "nginx", Version: "*", VersionEndExcluding: "1.20.1"}
	m, err := finding.NewMatch(server, c, "CVE-2021-23017", matching.Result{Matched: true, Evidence: entry, Flags: []matching.Flag{matching.DistroBackport}})
	if err != nil {
		t.Fatal(err)
	}
	if m.Key.Vendor != "f5" || m.Component != c || m.Evidence != entry || len(m.Flags) != 1 {
		t.Errorf("match = %+v", m)
	}
}

func TestNewMatchRejectsAResultThatDidNotMatch(t *testing.T) {
	t.Parallel()
	c := inventory.SoftwareComponent{Role: inventory.Application, Name: "nginx", Version: "1.20.1", Product: inventory.Product{Vendor: "f5", Name: "nginx"}}
	if _, err := finding.NewMatch(server, c, "CVE-2021-23017", matching.Result{}); !errors.Is(err, finding.ErrNotAMatch) {
		t.Errorf("NewMatch error = %v, want ErrNotAMatch", err)
	}
}
