package business

import (
	"fmt"
	"strings"
)

const notStated = "not stated"

// Brief is the Business Context as Markdown, for a model's prompt or a person
// to read. Every field has a line, so one the Customer has not stated reads
// "not stated" instead of being absent. Its text is the Customer's: data to
// weigh, never instructions to follow.
func (c Context) Brief(customer string) string {
	f := c.fields
	var b strings.Builder
	fmt.Fprintf(&b, "# Business context of %s\n", oneLine(customer))

	section(&b, "Profile",
		line("Summary", f.Profile.Summary),
		line("Sectors", labels(sectors, f.Profile.Sectors)),
		line("Organization type", label(organizationTypes, f.Profile.OrganizationType)),
		line("Employees", label(employeeRanges, f.Profile.Employees)),
		line("Annual revenue", label(revenueRanges, f.Profile.AnnualRevenue)),
		line("Mission", f.Profile.Mission),
		line("Vision", f.Profile.Vision),
	)
	section(&b, "Geography",
		line("Headquarters", f.Geography.Headquarters),
		line("Operates in", strings.Join(f.Geography.Countries, ", ")),
	)
	section(&b, "Operations",
		line("Critical services", services(f.Operations.CriticalServices)),
		line("Data it holds", labels(dataCategories, f.Operations.DataCategories)),
		line("Regulations it complies with", labels(regulations, f.Operations.Regulations)),
		line("Technology environments", labels(environments, f.Operations.Environments)),
	)
	section(&b, "Digital footprint and third parties",
		line("Domains", strings.Join(f.Footprint.Domains, ", ")),
		line("Brands", strings.Join(f.Footprint.Brands, ", ")),
		line("Technologies it depends on", strings.Join(f.Footprint.Technologies, ", ")),
		line("Third parties with access", strings.Join(f.Footprint.ThirdParties, ", ")),
	)
	section(&b, "Risk",
		line("Risk appetite", label(riskAppetites, f.Risk.Appetite)),
		line("Main concerns", labels(concerns, f.Risk.Concerns)),
		line("Past incidents", f.Risk.PastIncidents),
		line("Constraints on remediation", f.Risk.Constraints),
		line("Notes", f.Risk.Notes),
	)
	return b.String()
}

func section(b *strings.Builder, title string, lines ...string) {
	fmt.Fprintf(b, "\n## %s\n\n", title)
	for _, l := range lines {
		b.WriteString(l)
	}
}

// line keeps a multi-line value inside its list item by indenting it.
func line(name, value string) string {
	if value == "" {
		value = notStated
	}
	return fmt.Sprintf("- %s: %s\n", name, strings.ReplaceAll(value, "\n", "\n  "))
}

func label[T ~string](v vocabulary[T], code T) string {
	if code == "" {
		return ""
	}
	return v.label(code)
}

func labels[T ~string](v vocabulary[T], codes []T) string {
	names := make([]string, len(codes))
	for i, code := range codes {
		names[i] = v.label(code)
	}
	return strings.Join(names, ", ")
}

func services(list []CriticalService) string {
	items := make([]string, len(list))
	for i, s := range list {
		item := "\n- " + s.Name
		if s.Description != "" {
			item += ": " + oneLine(s.Description)
		}
		var facts []string
		if s.Impact != "" {
			facts = append(facts, "impact if lost "+impacts.label(s.Impact))
		}
		if s.MaxDowntime != "" {
			facts = append(facts, "maximum tolerable downtime "+downtimes.label(s.MaxDowntime))
		}
		if len(s.Assets) > 0 {
			facts = append(facts, "Assets: "+strings.Join(s.Assets, ", "))
		}
		if len(facts) > 0 {
			item += " (" + strings.Join(facts, "; ") + ")"
		}
		items[i] = item
	}
	return strings.Join(items, "")
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
