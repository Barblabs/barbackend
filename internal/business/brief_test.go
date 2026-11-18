package business_test

import (
	"strings"
	"testing"

	"barbackend/internal/business"
)

func TestBriefStatesEveryFieldByItsLabel(t *testing.T) {
	brief := mustNew(t, full()).Brief("PagoYa SA de CV")
	for _, want := range []string{
		"# Business context of PagoYa SA de CV\n",
		"- Sectors: Financial services, Technology\n",
		"- Employees: 250 to 999 employees\n",
		"- Operates in: MX, CO\n",
		"- Critical services: \n  - Card payments: Authorizes card payments. (impact if lost Critical: the business stops or faces severe legal or financial harm; maximum tolerable downtime 1 to 4 hours; Assets: srv-pay-01)\n",
		"- Regulations it complies with: PCI DSS, LFPDPPP (Mexico, personal data held by private parties)\n",
		"- Domains: pagos.example.mx\n",
		"- Risk appetite: Minimal: accepts only the lowest risks\n",
	} {
		if !strings.Contains(brief, want) {
			t.Errorf("Brief() lacks %q:\n%s", want, brief)
		}
	}
	if strings.Contains(brief, "not stated") {
		t.Errorf("Brief() of a full context says something is not stated:\n%s", brief)
	}
}

func TestBriefSaysWhatIsNotStated(t *testing.T) {
	var c business.Context
	brief := c.Brief("Acme")
	for _, want := range []string{"- Summary: not stated\n", "- Critical services: not stated\n", "- Notes: not stated\n"} {
		if !strings.Contains(brief, want) {
			t.Errorf("Brief() lacks %q:\n%s", want, brief)
		}
	}
}

func TestBriefKeepsMultiLineTextInsideItsItem(t *testing.T) {
	f := full()
	f.Risk.Notes = "First line.\n## Not a heading"
	if brief := mustNew(t, f).Brief("Acme"); !strings.Contains(brief, "- Notes: First line.\n  ## Not a heading\n") {
		t.Errorf("Brief() =\n%s", brief)
	}
}
