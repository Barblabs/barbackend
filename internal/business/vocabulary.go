package business

import "slices"

// Sector is an industry. The codes of STIX 2.1's industry-sector-ov come
// first, written as STIX writes them, so they compare with what threat
// intelligence says a threat targets; the rest name industries it leaves out,
// in the same style.
type Sector string

// OrganizationType is how a Customer is owned and organized.
type OrganizationType string

// EmployeeRange is how many people work for a Customer.
type EmployeeRange string

// RevenueRange is a Customer's annual revenue, in US dollars.
type RevenueRange string

// DataCategory is a kind of data a Customer holds that attackers seek or that
// a law protects.
type DataCategory string

// Regulation is a law, regulation or standard a Customer must comply with.
type Regulation string

// Environment is a kind of technology a Customer runs, each a different attack
// surface.
type Environment string

// Concern is a kind of attack a Customer worries about most.
type Concern string

// RiskAppetite is how much risk the Customer as a whole is willing to take,
// as its leadership sets it. How much each Critical Service tolerates is its
// Impact and MaxDowntime.
type RiskAppetite string

// Impact is how badly losing a Critical Service hurts the Customer.
type Impact string

// Downtime is how long a Critical Service can be unavailable before the harm
// is unacceptable, its maximum tolerable downtime.
type Downtime string

type term[T ~string] struct {
	code  T
	label string
}

type vocabulary[T ~string] []term[T]

func (v vocabulary[T]) codes() []T {
	codes := make([]T, len(v))
	for i, t := range v {
		codes[i] = t.code
	}
	return codes
}

func (v vocabulary[T]) has(code T) bool {
	return slices.ContainsFunc(v, func(t term[T]) bool { return t.code == code })
}

func (v vocabulary[T]) label(code T) string {
	i := slices.IndexFunc(v, func(t term[T]) bool { return t.code == code })
	if i < 0 {
		return string(code)
	}
	return v[i].label
}

var sectors = vocabulary[Sector]{
	{"agriculture", "Agriculture"},
	{"aerospace", "Aerospace"},
	{"automotive", "Automotive"},
	{"chemical", "Chemical"},
	{"commercial", "Commercial"},
	{"communications", "Communications"},
	{"construction", "Construction"},
	{"defense", "Defense"},
	{"education", "Education"},
	{"energy", "Energy"},
	{"entertainment", "Entertainment"},
	{"financial-services", "Financial services"},
	{"government", "Government"},
	{"government-emergency-services", "Government: emergency services"},
	{"government-local", "Government: local"},
	{"government-national", "Government: national"},
	{"government-public-services", "Government: public services"},
	{"government-regional", "Government: regional"},
	{"healthcare", "Healthcare"},
	{"hospitality-leisure", "Hospitality and leisure"},
	{"infrastructure", "Infrastructure"},
	{"infrastructure-dams", "Infrastructure: dams"},
	{"infrastructure-nuclear", "Infrastructure: nuclear"},
	{"infrastructure-water", "Infrastructure: water"},
	{"insurance", "Insurance"},
	{"manufacturing", "Manufacturing"},
	{"mining", "Mining"},
	{"non-profit", "Non-profit"},
	{"pharmaceuticals", "Pharmaceuticals"},
	{"retail", "Retail"},
	{"technology", "Technology"},
	{"telecommunications", "Telecommunications"},
	{"transportation", "Transportation"},
	{"utilities", "Utilities"},
	{"biotechnology", "Biotechnology"},
	{"cryptocurrency", "Cryptocurrency and digital assets"},
	{"e-commerce", "E-commerce"},
	{"food-beverage", "Food and beverage"},
	{"gaming", "Video games and betting"},
	{"legal", "Legal services"},
	{"logistics", "Logistics and shipping"},
	{"maritime", "Maritime and ports"},
	{"media", "Media and publishing"},
	{"oil-gas", "Oil and gas"},
	{"professional-services", "Professional services and consulting"},
	{"real-estate", "Real estate"},
	{"research", "Research"},
	{"semiconductors", "Semiconductors"},
}

var organizationTypes = vocabulary[OrganizationType]{
	{"private_company", "Private company"},
	{"public_company", "Publicly traded company"},
	{"subsidiary", "Subsidiary of a larger group"},
	{"state_owned", "State-owned company"},
	{"government", "Government entity"},
	{"non_profit", "Non-profit organization"},
	{"academic", "University or school"},
	{"cooperative", "Cooperative"},
	{"international_organization", "International organization"},
}

var employeeRanges = vocabulary[EmployeeRange]{
	{"1_9", "1 to 9 employees"},
	{"10_49", "10 to 49 employees"},
	{"50_249", "50 to 249 employees"},
	{"250_999", "250 to 999 employees"},
	{"1000_4999", "1,000 to 4,999 employees"},
	{"5000_9999", "5,000 to 9,999 employees"},
	{"10000_plus", "10,000 employees or more"},
}

var revenueRanges = vocabulary[RevenueRange]{
	{"under_1m", "under USD 1 million"},
	{"1m_5m", "USD 1 to 5 million"},
	{"5m_10m", "USD 5 to 10 million"},
	{"10m_50m", "USD 10 to 50 million"},
	{"50m_100m", "USD 50 to 100 million"},
	{"100m_250m", "USD 100 to 250 million"},
	{"250m_1b", "USD 250 million to 1 billion"},
	{"1b_10b", "USD 1 to 10 billion"},
	{"over_10b", "over USD 10 billion"},
}

var dataCategories = vocabulary[DataCategory]{
	{"personal_data", "Personal data"},
	{"sensitive_personal_data", "Sensitive personal data, such as religion or sexual orientation"},
	{"government_ids", "Government IDs, such as passports or tax IDs"},
	{"payment_cards", "Payment card data"},
	{"financial_data", "Financial and banking data"},
	{"tax_data", "Tax and accounting records"},
	{"health_data", "Health data"},
	{"biometric_data", "Biometric data"},
	{"children_data", "Children's data"},
	{"employee_data", "Employee and payroll data"},
	{"location_data", "Location data"},
	{"communications", "Email and message content"},
	{"credentials", "Customer credentials"},
	{"intellectual_property", "Intellectual property and trade secrets"},
	{"source_code", "Source code"},
	{"research_data", "Research data"},
	{"legal_data", "Legal and privileged documents"},
	{"operational_data", "Industrial and operational data"},
	{"classified_information", "Classified government information"},
}

var regulations = vocabulary[Regulation]{
	{"gdpr", "GDPR (EU)"},
	{"uk_gdpr", "UK GDPR"},
	{"lfpdppp", "LFPDPPP (Mexico, personal data held by private parties)"},
	{"lgpdppso", "LGPDPPSO (Mexico, personal data held by public bodies)"},
	{"lgpd", "LGPD (Brazil)"},
	{"habeas_data_co", "Ley 1581 (Colombia, personal data)"},
	{"ley_21719_cl", "Ley 21.719 (Chile, personal data)"},
	{"ley_25326_ar", "Ley 25.326 (Argentina, personal data)"},
	{"ccpa", "CCPA/CPRA (California)"},
	{"pipeda", "PIPEDA (Canada)"},
	{"pci_dss", "PCI DSS"},
	{"sox", "Sarbanes-Oxley"},
	{"glba", "GLBA (US financial)"},
	{"cnbv", "CNBV provisions (Mexico, financial)"},
	{"banxico", "Banco de México rules"},
	{"ley_fintech", "Ley Fintech (Mexico)"},
	{"cnsf", "CNSF provisions (Mexico, insurance)"},
	{"lfpiorpi", "LFPIORPI (Mexico, anti-money laundering)"},
	{"dora", "DORA (EU financial)"},
	{"nydfs_500", "NYDFS 23 NYCRR 500"},
	{"swift_csp", "SWIFT Customer Security Programme"},
	{"sec_cyber", "SEC cybersecurity disclosure rules"},
	{"hipaa", "HIPAA (US health)"},
	{"hitrust", "HITRUST"},
	{"nom_024_ssa3", "NOM-024-SSA3 (Mexico, electronic health records)"},
	{"nom_151", "NOM-151-SCFI (Mexico, data message retention)"},
	{"nis2", "NIS2 (EU)"},
	{"nerc_cip", "NERC CIP (energy)"},
	{"iec_62443", "IEC 62443 (industrial)"},
	{"tisax", "TISAX (automotive)"},
	{"cmmc", "CMMC (US defense)"},
	{"fedramp", "FedRAMP (US government cloud)"},
	{"fisma", "FISMA (US government)"},
	{"ferpa", "FERPA (US education)"},
	{"coppa", "COPPA (US, children online)"},
	{"iso_27001", "ISO/IEC 27001"},
	{"iso_27701", "ISO/IEC 27701"},
	{"iso_22301", "ISO 22301 (business continuity)"},
	{"soc_2", "SOC 2"},
	{"nist_csf", "NIST Cybersecurity Framework"},
	{"nist_800_53", "NIST SP 800-53"},
	{"cis_controls", "CIS Controls"},
	{"cobit", "COBIT"},
}

var environments = vocabulary[Environment]{
	{"on_premises", "On-premises data centers"},
	{"private_cloud", "Private cloud"},
	{"public_cloud", "Public cloud"},
	{"saas", "SaaS applications"},
	{"email_collaboration", "Email and collaboration suites"},
	{"erp", "ERP systems"},
	{"containers", "Containers and Kubernetes"},
	{"mainframe", "Mainframe"},
	{"legacy_systems", "Legacy or unsupported systems"},
	{"operational_technology", "Operational technology (OT, ICS)"},
	{"iot", "IoT devices"},
	{"public_web_apps", "Public websites and web applications"},
	{"public_apis", "Public APIs"},
	{"mobile_apps", "Mobile applications"},
	{"point_of_sale", "Point of sale terminals"},
	{"atms", "ATMs"},
	{"branch_offices", "Branch offices and stores"},
	{"remote_work", "Remote workforce"},
	{"byod", "Personal devices used for work"},
}

var concerns = vocabulary[Concern]{
	{"ransomware", "Ransomware and extortion"},
	{"data_theft", "Data theft"},
	{"accidental_exposure", "Accidental data exposure"},
	{"fraud", "Fraud"},
	{"business_email_compromise", "Business email compromise"},
	{"phishing", "Phishing"},
	{"social_engineering", "Social engineering by phone or message"},
	{"account_takeover", "Account takeover"},
	{"malware", "Malware"},
	{"vulnerability_exploitation", "Exploitation of vulnerabilities"},
	{"web_attacks", "Attacks on websites and applications"},
	{"espionage", "Espionage"},
	{"sabotage", "Sabotage and destructive attacks"},
	{"ddos", "Denial of service"},
	{"insider", "Insider threats"},
	{"supply_chain", "Supply chain attacks"},
	{"third_party_breach", "Breaches at suppliers"},
	{"hacktivism", "Hacktivism"},
	{"cryptojacking", "Cryptojacking"},
}

var riskAppetites = vocabulary[RiskAppetite]{
	{"averse", "Averse: avoids risk even at the cost of opportunities"},
	{"minimal", "Minimal: accepts only the lowest risks"},
	{"cautious", "Cautious: accepts some risk for clear benefits"},
	{"open", "Open: accepts risk for innovation or growth"},
	{"eager", "Eager: seeks risk for higher rewards"},
}

var impacts = vocabulary[Impact]{
	{"critical", "Critical: the business stops or faces severe legal or financial harm"},
	{"high", "High: major losses or customers affected"},
	{"medium", "Medium: noticeable disruption, with workarounds"},
	{"low", "Low: minor inconvenience"},
}

var downtimes = vocabulary[Downtime]{
	{"under_1h", "under 1 hour"},
	{"1h_4h", "1 to 4 hours"},
	{"4h_24h", "4 to 24 hours"},
	{"1d_3d", "1 to 3 days"},
	{"3d_7d", "3 to 7 days"},
	{"over_7d", "over 7 days"},
}

func Sectors() []Sector                     { return sectors.codes() }
func OrganizationTypes() []OrganizationType { return organizationTypes.codes() }
func EmployeeRanges() []EmployeeRange       { return employeeRanges.codes() }
func RevenueRanges() []RevenueRange         { return revenueRanges.codes() }
func DataCategories() []DataCategory        { return dataCategories.codes() }
func Regulations() []Regulation             { return regulations.codes() }
func Environments() []Environment           { return environments.codes() }
func Concerns() []Concern                   { return concerns.codes() }
func RiskAppetites() []RiskAppetite         { return riskAppetites.codes() }
func Impacts() []Impact                     { return impacts.codes() }
func Downtimes() []Downtime                 { return downtimes.codes() }
