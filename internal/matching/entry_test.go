package matching

import (
	"slices"
	"testing"

	"barbackend/internal/stixext"
)

func TestMatchEntry(t *testing.T) {
	t.Parallel()
	exact := func(version, update string) stixext.Affected {
		return stixext.Affected{Version: version, Update: update}
	}
	between := func(startIncluding, endExcluding string) stixext.Affected {
		return stixext.Affected{Version: "*", Update: "*", VersionStartIncluding: startIncluding, VersionEndExcluding: endExcluding}
	}
	tests := []struct {
		name    string
		version string
		entry   stixext.Affected
		matched bool
		flags   []Flag
	}{
		{"every version", "1.18.0", exact("*", "*"), true, nil},
		{"no versions", "", exact("-", "*"), true, nil},
		{"entry without a version", "1.18.0", exact("", ""), true, []Flag{VersionUnparsed}},

		{"exact equal", "5.6.1", exact("5.6.1", "*"), true, nil},
		{"exact equal with trailing zero", "5.6.1.0", exact("5.6.1", "*"), true, nil},
		{"exact older", "5.4.6", exact("5.6.1", "*"), false, nil},
		{"exact newer", "5.6.2", exact("5.6.1", "*"), false, nil},
		{"exact pre-release update", "2.0-beta9", exact("2.0", "beta9"), true, nil},
		{"exact pre-release update, release installed", "2.0", exact("2.0", "beta9"), false, nil},
		{"exact other update", "1.9.5p1", exact("1.9.5", "patch1"), true, []Flag{VersionUnparsed}},
		{"exact other update, same version", "1.9.5", exact("1.9.5", "patch1"), true, []Flag{VersionUnparsed}},
		{"exact other update, other version", "1.9.6", exact("1.9.5", "patch1"), false, nil},
		{"exact release line", "20.04.6", exact("20.04", "*"), true, []Flag{VersionUnparsed}},
		{"exact with revision", "5.6.1-2", exact("5.6.1", "*"), true, []Flag{DistroBackport}},
		{"exact not comparable", "1.0.1.2", exact("1.0.1f", "*"), true, []Flag{VersionUnparsed}},
		{"exact component unparsed", "latest", exact("5.6.1", "*"), true, []Flag{VersionUnparsed}},

		{"inside range", "1.18.0", between("0.6.18", "1.20.1"), true, nil},
		{"at start including", "0.6.18", between("0.6.18", "1.20.1"), true, nil},
		{"at end excluding", "1.20.1", between("0.6.18", "1.20.1"), false, nil},
		{"before range", "0.6.17", between("0.6.18", "1.20.1"), false, nil},
		{"range with revision", "1.0.1f-1ubuntu2.2", between("1.0.1", "1.0.1g"), true, []Flag{DistroBackport}},
		{"range component unparsed", "latest", between("0.6.18", "1.20.1"), true, []Flag{VersionUnparsed}},
		{"range bound not comparable", "1.0.1.2", between("1.0.1", "1.0.1g"), true, []Flag{VersionUnparsed}},
		{"excluding bound wins over doubt", "2.0.0", between("1.0.1", "1.0.1g"), false, nil},
		{"start excluding", "2.0", stixext.Affected{Version: "*", VersionStartExcluding: "2.0"}, false, nil},
		{"end including", "2.0", stixext.Affected{Version: "*", VersionEndIncluding: "2.0"}, true, nil},
		{"Cisco range", "17.9.4", between("17.9", "17.9.4a"), true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matched, flags := matchEntry(tt.version, tt.entry)
			if matched != tt.matched || !slices.Equal(flags, tt.flags) {
				t.Errorf("matchEntry(%q, %+v) = %t, %v; want %t, %v", tt.version, tt.entry, matched, flags, tt.matched, tt.flags)
			}
		})
	}
}
