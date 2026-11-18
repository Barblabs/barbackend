package ransomwarelive

import (
	"slices"
	"testing"

	"barbackend/internal/business"
)

func TestCanonicalDomain(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"www.neortho.com", "neortho.com"},
		{" www.californiacrossdock.com", "californiacrossdock.com"},
		{"HTTPS://WWW.Example.COM:8443/about?a=b#c", "example.com"},
		{"example.com.", "example.com"},
		{"fiber.net.id", "fiber.net.id"},
		{"owens-minor.com", "owens-minor.com"},
		{"www2.example.com", "www2.example.com"},
		{"", ""},
		{"Sice Previt S.p.A.", ""},
		{"i***************.c**", ""},
		{"w**.f*******.c**", ""},
		{"localhost", ""},
		{"-acme.com", ""},
		{"10.0.0.1", ""},
	}
	for _, tt := range tests {
		if got := canonicalDomain(tt.in); got != tt.want {
			t.Errorf("canonicalDomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSectorsOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		activity string
		want     []string
	}{
		{"Manufacturing", []string{"manufacturing"}},
		{"  retail & e-commerce ", []string{"retail", "e-commerce"}},
		{"Agriculture And Food Production", []string{"agriculture", "food-beverage"}},
		{"Hospitality", []string{"hospitality-leisure"}},
		{"Hospitality and Tourism", []string{"hospitality-leisure"}},
		{"Transportation/Logistics", []string{"transportation", "logistics"}},
		{"Public Sector", []string{"government"}},
		{"Media & Internet", []string{"media"}},
		{"Telecommunication", []string{"telecommunications"}},
		{"Pharmaceutical", []string{"pharmaceuticals"}},
		{"Not Found", nil},
		{"Other", nil},
		{"Consumer Services", nil},
		{"Business Services", nil},
		{"Banking", nil},
		{"", nil},
	}
	for _, tt := range tests {
		if got := sectorsOf(tt.activity); !slices.Equal(got, tt.want) {
			t.Errorf("sectorsOf(%q) = %v, want %v", tt.activity, got, tt.want)
		}
	}
}

func TestSectorsAreCodesOfTheBusinessVocabulary(t *testing.T) {
	t.Parallel()
	for activity, codes := range sectors {
		for _, code := range codes {
			if !slices.Contains(business.Sectors(), business.Sector(code)) {
				t.Errorf("%q maps to %q, which is not in business.Sectors()", activity, code)
			}
		}
	}
}
