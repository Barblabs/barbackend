// Package stixext holds barbattack's STIX conventions.
package stixext

import (
	"fmt"

	"github.com/TcM1911/stix2"
	"github.com/google/uuid"
)

var namespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/Barblabs/barbackend/stix"))

// TLPClear is the STIX 2.1 predefined TLP:CLEAR marking.
const TLPClear stix2.Identifier = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"

var (
	// BarbattackID is the identity that created every object barbattack mints.
	BarbattackID = ID(stix2.TypeIdentity, "barbattack")
	// KEVDefinitionID is the kev/1 extension definition.
	KEVDefinitionID = ID(stix2.TypeExtensionDefinition, "kev/1")
)

// ID returns the deterministic identifier of typ for key.
func ID(typ stix2.STIXType, key string) stix2.Identifier {
	return stix2.Identifier(fmt.Sprintf("%s--%s", typ, uuid.NewSHA1(namespace, []byte(string(typ)+":"+key))))
}

// VulnerabilityID returns the deterministic identifier of the Vulnerability for cveID.
func VulnerabilityID(cveID string) stix2.Identifier {
	return ID(stix2.TypeVulnerability, cveID)
}
