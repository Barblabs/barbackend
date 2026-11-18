package business_test

import (
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
