package business_test

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"barbackend/internal/business"
)

func full() business.Fields {
	return business.Fields{
		Profile: business.Profile{
			Summary:          "Online payments for small shops in Mexico.",
			Mission:          "Let every shop take cards.",
			Vision:           "The payments network of Latin America.",
			Sectors:          []business.Sector{"financial-services", "technology"},
			OrganizationType: "private_company",
			Employees:        "250_999",
			AnnualRevenue:    "100m_250m",
		},
		Geography: business.Geography{Headquarters: "MX", Countries: []string{"MX", "CO"}},
		Operations: business.Operations{
			CriticalServices: []business.CriticalService{{
				Name: "Card payments", Description: "Authorizes card payments.", Impact: "critical", MaxDowntime: "1h_4h", Assets: []string{"srv-pay-01"},
			}},
			DataCategories: []business.DataCategory{"payment_cards", "personal_data"},
			Regulations:    []business.Regulation{"pci_dss", "lfpdppp"},
			Environments:   []business.Environment{"public_cloud", "saas"},
		},
		Footprint: business.Footprint{
			Domains:      []string{"pagos.example.mx"},
			Brands:       []string{"PagoYa"},
			Technologies: []string{"AWS", "Microsoft 365"},
			ThirdParties: []string{"Nómina Fácil"},
		},
		Risk: business.Risk{
			Appetite:      "minimal",
			Concerns:      []business.Concern{"ransomware", "fraud"},
			PastIncidents: "Phishing in 2025.",
			Constraints:   "No changes on the last three days of the month.",
			Notes:         "Black Friday triples traffic.",
		},
	}
}

func mustNew(t *testing.T, f business.Fields) business.Context {
	t.Helper()
	c, err := business.New(f)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAStatedContextKeepsWhatTheCustomerSaid(t *testing.T) {
	want := full()
	got := mustNew(t, want).Fields()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Fields() = %+v, want %+v", got, want)
	}
}

func TestNewNormalizes(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*business.Fields)
		check func(business.Fields) bool
	}{
		{"trims text", func(f *business.Fields) { f.Profile.Summary = "  Payments.\n" }, func(f business.Fields) bool { return f.Profile.Summary == "Payments." }},
		{"drops blank and repeated entries regardless of case", func(f *business.Fields) { f.Footprint.Brands = []string{"PagoYa", " ", "pagoya", "Otra "} }, func(f business.Fields) bool {
			return slices.Equal(f.Footprint.Brands, []string{"PagoYa", "Otra"})
		}},
		{"drops repeated codes", func(f *business.Fields) { f.Risk.Concerns = []business.Concern{"fraud", "fraud"} }, func(f business.Fields) bool {
			return slices.Equal(f.Risk.Concerns, []business.Concern{"fraud"})
		}},
		{"keeps the host of a URL of any scheme, lowercased and without www", func(f *business.Fields) {
			f.Footprint.Domains = []string{"https://WWW.Example.mx/contacto", "example.mx.", "pagos.example.mx", "ftp://files.example.mx"}
		}, func(f business.Fields) bool {
			return slices.Equal(f.Footprint.Domains, []string{"example.mx", "pagos.example.mx", "files.example.mx"})
		}},
		{"upper-cases country codes", func(f *business.Fields) {
			f.Geography = business.Geography{Headquarters: " mx", Countries: []string{"mx", "co"}}
		}, func(f business.Fields) bool {
			return f.Geography.Headquarters == "MX" && slices.Equal(f.Geography.Countries, []string{"MX", "CO"})
		}},
		{"adds the headquarters to the countries", func(f *business.Fields) {
			f.Geography = business.Geography{Headquarters: "US", Countries: []string{"MX"}}
		}, func(f business.Fields) bool {
			return slices.Equal(f.Geography.Countries, []string{"US", "MX"})
		}},
		{"drops a critical service with nothing in it", func(f *business.Fields) {
			f.Operations.CriticalServices = append(f.Operations.CriticalServices, business.CriticalService{Name: " ", Assets: []string{""}})
		}, func(f business.Fields) bool { return len(f.Operations.CriticalServices) == 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := full()
			tt.edit(&f)
			if got := mustNew(t, f).Fields(); !tt.check(got) {
				t.Errorf("Fields() = %+v", got)
			}
		})
	}
}

func TestNewRejects(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	many := func(n int) []string {
		list := make([]string, n)
		for i := range list {
			list[i] = long(i + 1)
		}
		return list
	}
	tests := []struct {
		name string
		edit func(*business.Fields)
		path string
	}{
		{"a summary too long", func(f *business.Fields) { f.Profile.Summary = long(business.MaxSummary + 1) }, "profile.summary"},
		{"a mission too long", func(f *business.Fields) { f.Profile.Mission = long(business.MaxStatement + 1) }, "profile.mission"},
		{"notes too long", func(f *business.Fields) { f.Risk.Notes = long(business.MaxNarrative + 1) }, "risk.notes"},
		{"an unknown sector", func(f *business.Fields) { f.Profile.Sectors = []business.Sector{"banking"} }, "profile.sectors[0]"},
		{"an unknown employee range", func(f *business.Fields) { f.Profile.Employees = "many" }, "profile.employees"},
		{"an unknown regulation", func(f *business.Fields) { f.Operations.Regulations = []business.Regulation{"pci_dss", "pci"} }, "operations.regulations[1]"},
		{"an unknown impact", func(f *business.Fields) { f.Operations.CriticalServices[0].Impact = "severe" }, "operations.critical_services[0].impact"},
		{"an unknown downtime", func(f *business.Fields) { f.Operations.CriticalServices[0].MaxDowntime = "2h" }, "operations.critical_services[0].max_downtime"},
		{"an unknown country", func(f *business.Fields) { f.Geography.Countries = []string{"MX", "UK"} }, "geography.countries[1]"},
		{"an unknown headquarters", func(f *business.Fields) { f.Geography.Headquarters = "MEX" }, "geography.headquarters"},
		{"a malformed domain", func(f *business.Fields) { f.Footprint.Domains = []string{"pagos example"} }, "footprint.domains[0]"},
		{"an entry too long", func(f *business.Fields) { f.Footprint.Technologies = []string{long(business.MaxEntry + 1)} }, "footprint.technologies[0]"},
		{"too many entries", func(f *business.Fields) { f.Footprint.Brands = many(business.MaxEntries + 1) }, "footprint.brands"},
		{"a critical service without a name", func(f *business.Fields) {
			f.Operations.CriticalServices = []business.CriticalService{{Description: "Payroll."}}
		}, "operations.critical_services[0].name"},
		{"two critical services of one name", func(f *business.Fields) {
			f.Operations.CriticalServices = []business.CriticalService{{Name: "Payroll"}, {Name: "payroll"}}
		}, "operations.critical_services[1].name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := full()
			tt.edit(&f)
			_, err := business.New(f)
			if !errors.Is(err, business.ErrInvalidContext) {
				t.Fatalf("err = %v, want ErrInvalidContext", err)
			}
			problems := business.Problems(f)
			if len(problems) != 1 || !strings.HasPrefix(problems[0], tt.path+" ") {
				t.Errorf("Problems() = %q, want one about %s", problems, tt.path)
			}
		})
	}
}

func TestProblemsNamesEveryProblem(t *testing.T) {
	f := full()
	f.Profile.Employees = "many"
	f.Risk.Appetite = "none"
	if got := business.Problems(f); len(got) != 2 {
		t.Errorf("Problems() = %q, want two", got)
	}
}

func TestFieldsAreCopies(t *testing.T) {
	f := full()
	c := mustNew(t, f)
	f.Footprint.Domains[0] = "changed.mx"
	got := c.Fields()
	got.Operations.CriticalServices[0].Assets[0] = "changed"
	if again := c.Fields(); again.Footprint.Domains[0] != "pagos.example.mx" || again.Operations.CriticalServices[0].Assets[0] != "srv-pay-01" {
		t.Errorf("Fields() = %+v, changed through a copy", again)
	}
}

func TestAnUnstatedContextHasEveryKeyFieldAsAGap(t *testing.T) {
	var c business.Context
	if got := c.Gaps(); !slices.Equal(got, business.KeyFields()) {
		t.Errorf("Gaps() = %q, want %q", got, business.KeyFields())
	}
	if got := c.Fields(); got.Footprint.Domains == nil || got.Operations.CriticalServices == nil {
		t.Errorf("Fields() = %+v, want empty lists, not nil", got)
	}
	if got := mustNew(t, full()).Gaps(); len(got) != 0 {
		t.Errorf("Gaps() = %q, want none", got)
	}
}

func TestVocabulariesHaveDistinctCodes(t *testing.T) {
	lists := map[string][]string{
		"sectors":            strs(business.Sectors()),
		"organization types": strs(business.OrganizationTypes()),
		"employee ranges":    strs(business.EmployeeRanges()),
		"revenue ranges":     strs(business.RevenueRanges()),
		"data categories":    strs(business.DataCategories()),
		"regulations":        strs(business.Regulations()),
		"environments":       strs(business.Environments()),
		"concerns":           strs(business.Concerns()),
		"risk appetites":     strs(business.RiskAppetites()),
		"impacts":            strs(business.Impacts()),
		"downtimes":          strs(business.Downtimes()),
		"countries":          business.Countries(),
	}
	for name, codes := range lists {
		if len(codes) == 0 || len(slices.Compact(slices.Sorted(slices.Values(codes)))) != len(codes) || slices.Contains(codes, "") {
			t.Errorf("%s = %q, want distinct, non-blank codes", name, codes)
		}
	}
	if n := len(business.Countries()); n != 249 {
		t.Errorf("%d countries, want the 249 of ISO 3166-1", n)
	}
}

func strs[T ~string](codes []T) []string {
	out := make([]string, len(codes))
	for i, c := range codes {
		out[i] = string(c)
	}
	return out
}

func TestServicesOfAreThoseThatNameTheAsset(t *testing.T) {
	t.Parallel()
	f := full()
	f.Operations.CriticalServices = append(f.Operations.CriticalServices, business.CriticalService{Name: "Payroll", Assets: []string{"srv-hr-01"}})
	c := mustNew(t, f)

	got := c.ServicesOf("  SRV-PAY-01 ")

	if len(got) != 1 || got[0].Name != "Card payments" || got[0].Impact != "critical" {
		t.Errorf("services = %+v, want Card payments, matched ignoring case and spaces", got)
	}
	got[0].Assets[0] = "changed"
	if c.ServicesOf("srv-pay-01") == nil {
		t.Error("ServicesOf handed out the Context's own list")
	}
	if c.ServicesOf("srv-db-01") != nil {
		t.Error("a service that does not name the Asset was returned")
	}
}
