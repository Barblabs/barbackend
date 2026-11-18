package inventory_test

import (
	"errors"
	"testing"

	"barbackend/internal/inventory"
)

func TestNewOwnerEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		err   error
	}{
		{"canonical", "alice@example.com", "alice@example.com", nil},
		{"case folded", "Alice@Example.COM", "alice@example.com", nil},
		{"trimmed", " \talice@example.com\n", "alice@example.com", nil},
		{"empty", "", "", inventory.ErrEmptyOwnerEmail},
		{"whitespace", "   ", "", inventory.ErrEmptyOwnerEmail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := inventory.NewOwnerEmail(tt.input)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			if got.String() != tt.want {
				t.Errorf("NewOwnerEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCodesRoundTrip(t *testing.T) {
	t.Parallel()
	for _, k := range []inventory.AssetKind{inventory.Server, inventory.VirtualMachine, inventory.Workstation, inventory.NetworkDevice} {
		if got, err := inventory.ParseAssetKind(k.Code()); err != nil || got != k {
			t.Errorf("inventory.ParseAssetKind(%q) = %v, %v, want %v", k.Code(), got, err, k)
		}
	}
	for _, c := range []inventory.Criticality{inventory.CriticalityHigh, inventory.CriticalityMedium, inventory.CriticalityLow} {
		if got, err := inventory.ParseCriticality(c.Code()); err != nil || got != c {
			t.Errorf("inventory.ParseCriticality(%q) = %v, %v, want %v", c.Code(), got, err, c)
		}
	}
	if _, err := inventory.ParseCriticality(""); err == nil {
		t.Error("ParseCriticality accepted the empty code of Unknown")
	}
	for _, s := range []inventory.LifecycleStage{inventory.LifecycleProduction, inventory.LifecycleImplementation, inventory.LifecycleStock} {
		if got, err := inventory.ParseLifecycleStage(s.Code()); err != nil || got != s {
			t.Errorf("inventory.ParseLifecycleStage(%q) = %v, %v, want %v", s.Code(), got, err, s)
		}
	}
	if _, err := inventory.ParseLifecycleStage(""); err == nil {
		t.Error("ParseLifecycleStage accepted the empty code of Unknown")
	}
	for _, c := range []inventory.InformationClassification{inventory.ClassifiedPublic, inventory.ClassifiedPrivate, inventory.ClassifiedConfidential} {
		if got, err := inventory.ParseInformationClassification(c.Code()); err != nil || got != c {
			t.Errorf("inventory.ParseInformationClassification(%q) = %v, %v, want %v", c.Code(), got, err, c)
		}
	}
	if _, err := inventory.ParseInformationClassification(""); err == nil {
		t.Error("ParseInformationClassification accepted the empty code of Unclassified")
	}
}
