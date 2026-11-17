package news

import (
	"strings"

	"barbackend/internal/business"
)

// sectorNames are the sectors as the Security Team reads them, in Spanish.
var sectorNames = map[business.Sector]string{
	"agriculture": "agricultura", "aerospace": "aeroespacial", "automotive": "automotriz",
	"chemical": "química", "commercial": "comercio", "communications": "comunicaciones",
	"construction": "construcción", "defense": "defensa", "education": "educación",
	"energy": "energía", "entertainment": "entretenimiento", "financial-services": "servicios financieros",
	"government": "gobierno", "government-emergency-services": "servicios de emergencia",
	"government-local": "gobierno local", "government-national": "gobierno nacional",
	"government-public-services": "servicios públicos de gobierno", "government-regional": "gobierno estatal o regional",
	"healthcare": "salud", "hospitality-leisure": "hotelería y turismo", "infrastructure": "infraestructura",
	"infrastructure-dams": "presas", "infrastructure-nuclear": "nuclear", "infrastructure-water": "agua",
	"insurance": "seguros", "manufacturing": "manufactura", "mining": "minería", "non-profit": "sin fines de lucro",
	"pharmaceuticals": "farmacéutica", "retail": "comercio minorista", "technology": "tecnología",
	"telecommunications": "telecomunicaciones", "transportation": "transporte", "utilities": "servicios públicos",
	"biotechnology": "biotecnología", "cryptocurrency": "criptoactivos", "e-commerce": "comercio electrónico",
	"food-beverage": "alimentos y bebidas", "gaming": "videojuegos y apuestas", "legal": "servicios legales",
	"logistics": "logística", "maritime": "marítimo y puertos", "media": "medios",
	"oil-gas": "petróleo y gas", "professional-services": "servicios profesionales", "real-estate": "inmobiliario",
	"research": "investigación", "semiconductors": "semiconductores",
}

// concernNames are the kinds of attack as the Security Team reads them, in
// Spanish.
var concernNames = map[business.Concern]string{
	"ransomware": "ransomware y extorsión", "data_theft": "robo de datos", "accidental_exposure": "exposición accidental de datos",
	"fraud": "fraude", "business_email_compromise": "compromiso de correo empresarial", "phishing": "phishing",
	"social_engineering": "ingeniería social", "account_takeover": "robo de cuentas", "malware": "malware",
	"vulnerability_exploitation": "explotación de vulnerabilidades", "web_attacks": "ataques a sitios y aplicaciones",
	"espionage": "espionaje", "sabotage": "sabotaje", "ddos": "denegación de servicio", "insider": "amenaza interna",
	"supply_chain": "ataque a la cadena de suministro", "third_party_breach": "brecha en un proveedor",
	"hacktivism": "hacktivismo", "cryptojacking": "cryptojacking",
}

// SectorName is s as the Security Team reads it.
func SectorName(s business.Sector) string {
	if name, ok := sectorNames[s]; ok {
		return name
	}
	return string(s)
}

// ConcernName is c as the Security Team reads it.
func ConcernName(c business.Concern) string {
	if name, ok := concernNames[c]; ok {
		return name
	}
	return string(c)
}

func joinSectors(sectors []business.Sector) string {
	names := make([]string, len(sectors))
	for i, s := range sectors {
		names[i] = SectorName(s)
	}
	return strings.Join(names, ", ")
}
