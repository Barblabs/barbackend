package httpapi

import (
	"barbackend/internal/business"
	"github.com/danielgtaylor/huma/v2"
)

// businessContextFields is business.Fields on the wire, in the shape
// business.Schema names. Every field is sent: blank text, a blank code or an
// empty list means not stated.
type businessContextFields struct {
	_          struct{}         `additionalProperties:"true"`
	Profile    profileFields    `json:"profile"`
	Geography  geographyFields  `json:"geography"`
	Operations operationsFields `json:"operations"`
	Footprint  footprintFields  `json:"footprint"`
	Risk       riskFields       `json:"risk"`
}

type profileFields struct {
	_                struct{}             `additionalProperties:"true"`
	Summary          string               `json:"summary" doc:"What the Customer does, for whom and how, up to 2000 characters"`
	Mission          string               `json:"mission" doc:"Up to 1000 characters"`
	Vision           string               `json:"vision" doc:"Up to 1000 characters"`
	Sectors          []sectorCode         `json:"sectors" doc:"STIX 2.1 industry-sector-ov codes"`
	OrganizationType organizationTypeCode `json:"organization_type"`
	Employees        employeeRangeCode    `json:"employees"`
	AnnualRevenue    revenueRangeCode     `json:"annual_revenue" doc:"In US dollars per year"`
}

type geographyFields struct {
	_            struct{} `additionalProperties:"true"`
	Headquarters string   `json:"headquarters" doc:"ISO 3166-1 alpha-2 code, such as MX"`
	Countries    []string `json:"countries" doc:"ISO 3166-1 alpha-2 codes of where it operates, its headquarters among them"`
}

type operationsFields struct {
	_                struct{}               `additionalProperties:"true"`
	CriticalServices []criticalServiceField `json:"critical_services" doc:"Up to 25"`
	DataCategories   []dataCategoryCode     `json:"data_categories"`
	Regulations      []regulationCode       `json:"regulations"`
	Environments     []environmentCode      `json:"environments"`
}

type criticalServiceField struct {
	_           struct{}     `additionalProperties:"true"`
	Name        string       `json:"name" doc:"Up to 200 characters, unique regardless of case"`
	Description string       `json:"description" doc:"Up to 1000 characters"`
	Impact      impactCode   `json:"impact" doc:"How badly losing it hurts the Customer"`
	MaxDowntime downtimeCode `json:"max_downtime" doc:"How long it can be down before the harm is unacceptable"`
	Assets      []string     `json:"assets" doc:"Names of the Assets that run it, as the CMDB Source writes them"`
}

type footprintFields struct {
	_            struct{} `additionalProperties:"true"`
	Domains      []string `json:"domains" doc:"Domain names, such as example.com; a URL keeps only its host"`
	Brands       []string `json:"brands"`
	Technologies []string `json:"technologies" doc:"Platforms, SaaS and products it depends on that are not Assets"`
	ThirdParties []string `json:"third_parties" doc:"Suppliers and partners with access to its systems or data"`
}

type riskFields struct {
	_             struct{}         `additionalProperties:"true"`
	Appetite      riskAppetiteCode `json:"appetite" doc:"How much risk the Customer as a whole takes, as its leadership sets it"`
	Concerns      []concernCode    `json:"concerns"`
	PastIncidents string           `json:"past_incidents" doc:"Up to 4000 characters"`
	Constraints   string           `json:"constraints" doc:"What limits remediation, such as maintenance windows; up to 4000 characters"`
	Notes         string           `json:"notes" doc:"Up to 4000 characters"`
}

type (
	sectorCode           string
	organizationTypeCode string
	employeeRangeCode    string
	revenueRangeCode     string
	dataCategoryCode     string
	regulationCode       string
	environmentCode      string
	concernCode          string
	riskAppetiteCode     string
	impactCode           string
	downtimeCode         string
)

func (sectorCode) Schema(huma.Registry) *huma.Schema { return codeSchema(business.Sectors()) }
func (organizationTypeCode) Schema(huma.Registry) *huma.Schema {
	return optionalCodeSchema(business.OrganizationTypes())
}
func (employeeRangeCode) Schema(huma.Registry) *huma.Schema {
	return optionalCodeSchema(business.EmployeeRanges())
}
func (revenueRangeCode) Schema(huma.Registry) *huma.Schema {
	return optionalCodeSchema(business.RevenueRanges())
}
func (dataCategoryCode) Schema(huma.Registry) *huma.Schema {
	return codeSchema(business.DataCategories())
}
func (regulationCode) Schema(huma.Registry) *huma.Schema { return codeSchema(business.Regulations()) }
func (environmentCode) Schema(huma.Registry) *huma.Schema {
	return codeSchema(business.Environments())
}
func (concernCode) Schema(huma.Registry) *huma.Schema { return codeSchema(business.Concerns()) }
func (riskAppetiteCode) Schema(huma.Registry) *huma.Schema {
	return optionalCodeSchema(business.RiskAppetites())
}
func (impactCode) Schema(huma.Registry) *huma.Schema { return optionalCodeSchema(business.Impacts()) }
func (downtimeCode) Schema(huma.Registry) *huma.Schema {
	return optionalCodeSchema(business.Downtimes())
}

func codeSchema[T ~string](values []T) *huma.Schema {
	enum := make([]any, len(values))
	for i, v := range values {
		enum[i] = string(v)
	}
	return &huma.Schema{Type: huma.TypeString, Enum: enum}
}

// optionalCodeSchema allows blank, for not stated.
func optionalCodeSchema[T ~string](values []T) *huma.Schema {
	s := codeSchema(values)
	s.Enum = append([]any{""}, s.Enum...)
	return s
}

func convert[To, From ~string](values []From) []To {
	out := make([]To, len(values))
	for i, v := range values {
		out[i] = To(v)
	}
	return out
}

func (f businessContextFields) fields() business.Fields {
	services := make([]business.CriticalService, len(f.Operations.CriticalServices))
	for i, s := range f.Operations.CriticalServices {
		services[i] = business.CriticalService{
			Name: s.Name, Description: s.Description, Assets: s.Assets,
			Impact: business.Impact(s.Impact), MaxDowntime: business.Downtime(s.MaxDowntime),
		}
	}
	return business.Fields{
		Profile: business.Profile{
			Summary: f.Profile.Summary, Mission: f.Profile.Mission, Vision: f.Profile.Vision,
			Sectors:          convert[business.Sector](f.Profile.Sectors),
			OrganizationType: business.OrganizationType(f.Profile.OrganizationType),
			Employees:        business.EmployeeRange(f.Profile.Employees),
			AnnualRevenue:    business.RevenueRange(f.Profile.AnnualRevenue),
		},
		Geography: business.Geography{Headquarters: f.Geography.Headquarters, Countries: f.Geography.Countries},
		Operations: business.Operations{
			CriticalServices: services,
			DataCategories:   convert[business.DataCategory](f.Operations.DataCategories),
			Regulations:      convert[business.Regulation](f.Operations.Regulations),
			Environments:     convert[business.Environment](f.Operations.Environments),
		},
		Footprint: business.Footprint{
			Domains: f.Footprint.Domains, Brands: f.Footprint.Brands,
			Technologies: f.Footprint.Technologies, ThirdParties: f.Footprint.ThirdParties,
		},
		Risk: business.Risk{
			Appetite:      business.RiskAppetite(f.Risk.Appetite),
			Concerns:      convert[business.Concern](f.Risk.Concerns),
			PastIncidents: f.Risk.PastIncidents, Constraints: f.Risk.Constraints, Notes: f.Risk.Notes,
		},
	}
}

func newBusinessContextFields(f business.Fields) businessContextFields {
	services := make([]criticalServiceField, len(f.Operations.CriticalServices))
	for i, s := range f.Operations.CriticalServices {
		services[i] = criticalServiceField{
			Name: s.Name, Description: s.Description, Assets: s.Assets,
			Impact: impactCode(s.Impact), MaxDowntime: downtimeCode(s.MaxDowntime),
		}
	}
	return businessContextFields{
		Profile: profileFields{
			Summary: f.Profile.Summary, Mission: f.Profile.Mission, Vision: f.Profile.Vision,
			Sectors:          convert[sectorCode](f.Profile.Sectors),
			OrganizationType: organizationTypeCode(f.Profile.OrganizationType),
			Employees:        employeeRangeCode(f.Profile.Employees),
			AnnualRevenue:    revenueRangeCode(f.Profile.AnnualRevenue),
		},
		Geography: geographyFields{Headquarters: f.Geography.Headquarters, Countries: f.Geography.Countries},
		Operations: operationsFields{
			CriticalServices: services,
			DataCategories:   convert[dataCategoryCode](f.Operations.DataCategories),
			Regulations:      convert[regulationCode](f.Operations.Regulations),
			Environments:     convert[environmentCode](f.Operations.Environments),
		},
		Footprint: footprintFields{
			Domains: f.Footprint.Domains, Brands: f.Footprint.Brands,
			Technologies: f.Footprint.Technologies, ThirdParties: f.Footprint.ThirdParties,
		},
		Risk: riskFields{
			Appetite:      riskAppetiteCode(f.Risk.Appetite),
			Concerns:      convert[concernCode](f.Risk.Concerns),
			PastIncidents: f.Risk.PastIncidents, Constraints: f.Risk.Constraints, Notes: f.Risk.Notes,
		},
	}
}
