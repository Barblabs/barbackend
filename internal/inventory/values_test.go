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

func TestOwnerEmailsDifferingInCaseAreTheSameOwner(t *testing.T) {
	if mustOwner(t, "Alice@example.com") != mustOwner(t, "alice@example.com ") {
		t.Error("emails differing only in case and spacing should be equal")
	}
}
