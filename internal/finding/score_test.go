package finding_test

import (
	"testing"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

func vulnerability(t *testing.T, opts ...stix2.STIXOption) *stix2.Vulnerability {
	t.Helper()
	v, err := stix2.NewVulnerability("CVE-2021-23017", opts...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func nvdWith(cvss ...stixext.CVSS) stix2.STIXOption {
	return stix2.OptionExtension(string(stixext.NVDDefinitionID), stixext.NewNVD(stixext.NVD{CVSS: cvss}))
}

func TestScoreInputsReadsEveryFeed(t *testing.T) {
	t.Parallel()
	v := vulnerability(t,
		nvdWith(
			stixext.CVSS{Version: "3.1", BaseScore: 8.1, Type: "Primary"},
			stixext.CVSS{Version: "4.0", BaseScore: 9.3, Type: "Secondary"},
		),
		stix2.OptionExtension(string(stixext.EPSSDefinitionID), stixext.NewEPSS(stixext.EPSS{Probability: 0.42, Percentile: 0.9})),
		stix2.OptionExtension(string(stixext.KEVDefinitionID), stixext.NewKEV(stixext.KEV{DateAdded: "2021-12-10"})),
	)
	in := finding.ScoreInputs(v, finding.AssetValues{Criticality: inventory.CriticalityHigh, Exposure: inventory.Internal, Lifecycle: inventory.LifecycleStock}, false)
	if in.CVSS == nil || *in.CVSS != 8.1 {
		t.Errorf("CVSS = %v, want NVD's Primary 8.1 over the Secondary", in.CVSS)
	}
	if in.EPSS == nil || *in.EPSS != 0.42 {
		t.Errorf("EPSS = %v, want 0.42", in.EPSS)
	}
	if !in.KEVListed || in.KEVStale || in.Criticality != inventory.CriticalityHigh || in.Exposure != inventory.Internal ||
		in.Lifecycle != inventory.LifecycleStock {
		t.Errorf("inputs = %+v", in)
	}
}

func TestScoreInputsTakesTheNewestSecondaryWithoutAPrimary(t *testing.T) {
	t.Parallel()
	v := vulnerability(t, nvdWith(
		stixext.CVSS{Version: "3.1", BaseScore: 7.5, Type: "Secondary"},
		stixext.CVSS{Version: "4.0", BaseScore: 8.7, Type: "Secondary"},
	))
	if in := finding.ScoreInputs(v, finding.AssetValues{Criticality: inventory.CriticalityLow}, false); in.CVSS == nil || *in.CVSS != 8.7 {
		t.Errorf("CVSS = %v, want the CVSS 4.0 Secondary 8.7", in.CVSS)
	}
}

func TestScoreInputsLeavesMissingAndOutOfRangeValuesUnknown(t *testing.T) {
	t.Parallel()
	v := vulnerability(t,
		nvdWith(stixext.CVSS{Version: "3.1", BaseScore: 11, Type: "Primary"}),
		stix2.OptionExtension(string(stixext.EPSSDefinitionID), stixext.NewEPSS(stixext.EPSS{Probability: 1.5})),
	)
	in := finding.ScoreInputs(v, finding.AssetValues{}, true)
	if in.CVSS != nil || in.EPSS != nil || in.KEVListed || !in.KEVStale {
		t.Errorf("inputs = %+v, want CVSS and EPSS unknown, not listed and stale", in)
	}
	if in := finding.ScoreInputs(vulnerability(t), finding.AssetValues{Criticality: inventory.CriticalityLow, Exposure: inventory.Internal}, false); in.CVSS != nil || in.EPSS != nil || in.KEVListed {
		t.Errorf("inputs without extensions = %+v, want nothing known", in)
	}
}
