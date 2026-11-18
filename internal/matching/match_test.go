package matching_test

import (
	"slices"
	"testing"

	"barbackend/internal/inventory"
	"barbackend/internal/matching"
	"barbackend/internal/stixext"
)

func component(vendor, name, version string) inventory.SoftwareComponent {
	return inventory.SoftwareComponent{
		Role:    inventory.Application,
		Name:    name,
		Version: version,
		Product: inventory.Product{Vendor: vendor, Name: name},
	}
}

func vulnerability(entries ...stixext.Affected) stixext.NVD {
	return stixext.NVD{VulnStatus: "Analyzed", Affected: entries}
}

func exact(vendor, product, version, update string) stixext.Affected {
	return stixext.Affected{Vendor: vendor, Product: product, Version: version, Update: update}
}

func between(vendor, product, startIncluding, endExcluding string) stixext.Affected {
	return stixext.Affected{
		Vendor: vendor, Product: product, Version: "*", Update: "*",
		VersionStartIncluding: startIncluding, VersionEndExcluding: endExcluding,
	}
}

// The NVD entries of the examples in ADR 0015.
var (
	cve202123017 = vulnerability(between("f5", "nginx", "0.6.18", "1.20.1"))
	cve20243094  = vulnerability(exact("tukaani", "xz", "5.6.0", "*"), exact("tukaani", "xz", "5.6.1", "*"))
	cve202144228 = vulnerability(
		exact("apache", "log4j", "2.0", "beta9"),
		exact("apache", "log4j", "2.0", "rc1"),
		exact("apache", "log4j", "2.0", "rc2"),
		between("apache", "log4j", "2.0.1", "2.3.1"),
		between("apache", "log4j", "2.4.0", "2.12.2"),
		between("apache", "log4j", "2.13.0", "2.15.0"),
	)
	cve20140160 = vulnerability(between("openssl", "openssl", "1.0.1", "1.0.1g"))
	cve20213156 = vulnerability(
		between("sudo_project", "sudo", "1.8.2", "1.8.32"),
		between("sudo_project", "sudo", "1.9.0", "1.9.5"),
		exact("sudo_project", "sudo", "1.9.5", "patch1"),
	)
	cve202320198 = vulnerability(between("cisco", "ios_xe", "17.9", "17.9.4a"))
	cve20201472  = vulnerability(exact("canonical", "ubuntu_linux", "20.04", "*"))
	cve202222965 = vulnerability(
		between("vmware", "spring_framework", "5.3.0", "5.3.18"),
		between("vmware", "spring_framework", "5.2.0", "5.2.20"),
	)
)

func TestMatchExamplesOfADR0015(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		c       inventory.SoftwareComponent
		n       stixext.NVD
		matched bool
		flags   []matching.Flag
	}{
		{"1 nginx in range", component("f5", "nginx", "1.18.0"), cve202123017, true, nil},
		{"2 nginx at fixed version", component("f5", "nginx", "1.20.1"), cve202123017, false, nil},
		{"3 nginx at first vulnerable version", component("f5", "nginx", "0.6.18"), cve202123017, true, nil},
		{"4 xz backdoored version", component("tukaani", "xz", "5.6.1"), cve20243094, true, nil},
		{"5 xz older version", component("tukaani", "xz", "5.4.6"), cve20243094, false, nil},
		{"6 log4j in range", component("apache", "log4j", "2.14.1"), cve202144228, true, nil},
		{"7 log4j at fixed version", component("apache", "log4j", "2.12.2"), cve202144228, false, nil},
		{"8 log4j beta", component("apache", "log4j", "2.0-beta9"), cve202144228, true, nil},
		{"9 openssl Heartbleed", component("openssl", "openssl", "1.0.1f"), cve20140160, true, nil},
		{"10 openssl fixed", component("openssl", "openssl", "1.0.1g"), cve20140160, false, nil},
		{"11 openssl from Ubuntu", component("openssl", "openssl", "1.0.1f-1ubuntu2.2"), cve20140160, true, []matching.Flag{matching.DistroBackport}},
		{"12 sudo with p2", component("sudo_project", "sudo", "1.8.31p2"), cve20213156, true, nil},
		{"13 sudo p1 against patch1", component("sudo_project", "sudo", "1.9.5p1"), cve20213156, true, []matching.Flag{matching.VersionUnparsed}},
		{"14 Cisco IOS XE", component("cisco", "ios_xe", "17.9.4"), cve202320198, true, nil},
		{"15 Ubuntu release", component("canonical", "ubuntu_linux", "20.04"), cve20201472, true, nil},
		{"16 Spring4Shell, condition not checked", component("vmware", "spring_framework", "5.3.17"), cve202222965, true, nil},
		{"17 version not a version", component("f5", "nginx", "latest"), cve202123017, true, []matching.Flag{matching.VersionUnparsed}},
		{"18 no Product", inventory.SoftwareComponent{Role: inventory.Application, Name: "nginx", Version: "1.18.0"}, cve202123017, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := matching.Match(tt.c, tt.n)
			if got.Matched != tt.matched || !slices.Equal(got.Flags, tt.flags) {
				t.Errorf("Match = %t, %v; want %t, %v", got.Matched, got.Flags, tt.matched, tt.flags)
			}
		})
	}
}

func TestMatchIgnoresCaseOfProduct(t *testing.T) {
	t.Parallel()
	if got := matching.Match(component("F5", "NGINX", "1.18.0"), cve202123017); !got.Matched {
		t.Errorf("Match = %+v, want a match", got)
	}
}

func TestMatchSkipsOtherProducts(t *testing.T) {
	t.Parallel()
	if got := matching.Match(component("f5", "nginx", "1.18.0"), cve20243094); got.Matched {
		t.Errorf("Match = %+v, want no match", got)
	}
}

func TestMatchNeverMatchesARejectedVulnerability(t *testing.T) {
	t.Parallel()
	n := cve202123017
	n.VulnStatus = "Rejected"
	if got := matching.Match(component("f5", "nginx", "1.18.0"), n); got.Matched {
		t.Errorf("Match = %+v, want no match", got)
	}
}

func TestMatchKeepsAnEntryWithoutFlagsAsEvidence(t *testing.T) {
	t.Parallel()
	certain := between("apache", "log4j", "2.13.0", "2.15.0")
	n := vulnerability(exact("apache", "log4j", "latest", "*"), certain)
	got := matching.Match(component("apache", "log4j", "2.14.1"), n)
	if !got.Matched || len(got.Flags) != 0 || got.Evidence != certain {
		t.Errorf("Match = %+v, want the certain entry %+v without flags", got, certain)
	}
}

func TestMatchKeepsTheFirstFlaggedEntryWhenNoneIsCertain(t *testing.T) {
	t.Parallel()
	first := exact("sudo_project", "sudo", "1.9.5", "patch1")
	n := vulnerability(first, exact("sudo_project", "sudo", "1.9.5", "patch2"))
	got := matching.Match(component("sudo_project", "sudo", "1.9.5p1"), n)
	if !got.Matched || got.Evidence != first || !slices.Equal(got.Flags, []matching.Flag{matching.VersionUnparsed}) {
		t.Errorf("Match = %+v, want %+v flagged version_unparsed", got, first)
	}
}
