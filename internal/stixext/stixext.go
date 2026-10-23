// Package stixext holds barbattack's STIX conventions.
package stixext

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/TcM1911/stix2"
	"github.com/google/uuid"
)

var namespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/Barblabs/barbackend/stix"))

var (
	cveIDPattern    = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cveTokenPattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
)

// TLPClear is the STIX 2.1 predefined TLP:CLEAR marking.
const TLPClear stix2.Identifier = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"

var (
	// BarbattackID is the identity that created every object barbattack mints.
	BarbattackID     = ID(stix2.TypeIdentity, "barbattack")
	KEVDefinitionID  = ID(stix2.TypeExtensionDefinition, "kev/1")
	NVDDefinitionID  = ID(stix2.TypeExtensionDefinition, "nvd/1")
	EPSSDefinitionID = ID(stix2.TypeExtensionDefinition, "epss/1")
)

// CVEID returns id trimmed and upper-cased, and whether it is a CVE ID.
func CVEID(id string) (string, bool) {
	id = strings.ToUpper(strings.TrimSpace(id))
	return id, cveIDPattern.MatchString(id)
}

// CVEIDs returns the unique CVE IDs mentioned in text, upper-cased.
func CVEIDs(text string) []string {
	matches := cveTokenPattern.FindAllString(text, -1)
	ids := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		id, ok := CVEID(match)
		if !ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

// ID returns the deterministic identifier of typ for key.
func ID(typ stix2.STIXType, key string) stix2.Identifier {
	return stix2.Identifier(fmt.Sprintf("%s--%s", typ, uuid.NewSHA1(namespace, []byte(string(typ)+":"+key))))
}

// VulnerabilityID returns the deterministic identifier of the Vulnerability for cveID.
func VulnerabilityID(cveID string) stix2.Identifier {
	return ID(stix2.TypeVulnerability, cveID)
}
