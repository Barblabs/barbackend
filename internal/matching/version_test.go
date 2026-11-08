package matching_test

import (
	"errors"
	"testing"

	"barbackend/internal/matching"
)

func mustParse(t *testing.T, s string) matching.Version {
	t.Helper()
	v, err := matching.ParseVersion(s)
	if err != nil {
		t.Fatalf("ParseVersion(%q): %v", s, err)
	}
	return v
}

func TestParseVersionRejectsUnusableText(t *testing.T) {
	for _, s := range []string{"", "   ", "latest", "*", "-", "v", "abc", "1..2", "1.", "1.0-", "2.0-beta9-"} {
		t.Run(s, func(t *testing.T) {
			if _, err := matching.ParseVersion(s); !errors.Is(err, matching.ErrUnparsedVersion) {
				t.Fatalf("ParseVersion(%q) error = %v, want ErrUnparsedVersion", s, err)
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.9", "1.10", -1},
		{"1.18", "1.18.0", 0},
		{"1.02", "1.2", 0},
		{"1.18.0", "1.20.1", -1},
		{"0.6.18", "0.6.18", 0},
		{"1.0.1f", "1.0.1g", -1},
		{"1.0.1F", "1.0.1f", 0},
		{"1.8.31p2", "1.8.32", -1},
		{"17.9.4", "17.9.4a", -1},
		{"2.14.1", "2.15.0", -1},
		{"2.0-beta9", "2.0", -1},
		{"2.0-beta9", "2.0-rc1", -1},
		{"2.0-rc1", "2.0-rc2", -1},
		{"2.0-beta.2", "2.0-beta2", 0},
		{"1.0.1f-1ubuntu2.2", "1.0.1g", -1},
		{"1.0.1f-1ubuntu2.2", "1.0.1f", 0},
		{"v1.18.0", "1.18.0", 0},
		{"1:1.18.0-6ubuntu14.4", "1.18.0", 0},
		{"99999999999999999999.1", "99999999999999999999.0", 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			a, b := mustParse(t, tt.a), mustParse(t, tt.b)
			if got, ok := a.Compare(b); got != tt.want || !ok {
				t.Errorf("Compare = %d, %t; want %d, true", got, ok, tt.want)
			}
			if got, ok := b.Compare(a); got != -tt.want || !ok {
				t.Errorf("reverse Compare = %d, %t; want %d, true", got, ok, -tt.want)
			}
		})
	}
}

func TestVersionCompareNotComparable(t *testing.T) {
	tests := []struct {
		name string
		a, b matching.Version
	}{
		{"number meets letters", mustParse(t, "1.0.1f"), mustParse(t, "1.0.1.2")},
		{"zero Version", matching.Version{}, mustParse(t, "1.0")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := tt.a.Compare(tt.b); ok {
				t.Error("Compare is comparable, want not comparable")
			}
			if _, ok := tt.b.Compare(tt.a); ok {
				t.Error("reverse Compare is comparable, want not comparable")
			}
		})
	}
}

func TestVersionHasRevision(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"1.18.0", false},
		{"2.0-beta9", false},
		{"1.0.1f-1ubuntu2.2", true},
		{"2.0-rc1-1ubuntu1", true},
		{"2.0-preview1", true},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := mustParse(t, tt.s).HasRevision(); got != tt.want {
				t.Errorf("HasRevision = %t, want %t", got, tt.want)
			}
		})
	}
}
