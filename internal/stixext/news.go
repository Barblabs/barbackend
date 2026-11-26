package stixext

import (
	"strings"

	"github.com/TcM1911/stix2"
)

var (
	NewsDefinitionID   = ID(stix2.TypeExtensionDefinition, "news/1")
	VictimDefinitionID = ID(stix2.TypeExtensionDefinition, "victim/1")
)

// Kinds of News Item (ADR 0025).
const (
	// NewsArticle is an article of a news site: text the Reader reads.
	NewsArticle = "article"
	// NewsLeakPost is a post on a leak site, as a tracker relays it: the
	// attacker's own claim.
	NewsLeakPost = "leak_post"
)

// News is the news/1 property extension of a News Item's report (ADR 0010).
type News struct {
	ExtensionType string `json:"extension_type"`
	// Feed is the Feed that published it, as registered.
	Feed string `json:"feed"`
	// Kind is NewsArticle or NewsLeakPost.
	Kind string `json:"kind"`
	// Language is BCP 47, when the Feed says.
	Language string `json:"language,omitempty"`
	// Attacker is who claims the attack, as the Feed names it, for a leak
	// post.
	Attacker string `json:"attacker,omitempty"`
	// Link is the item's page at its source.
	Link string `json:"link,omitempty"`
}

func NewNews(n News) News {
	n.ExtensionType = "property-extension"
	return n
}

// NewsOf is the news/1 extension of r, and whether r has one.
func NewsOf(r *stix2.Report) (News, bool) {
	return decode[News](r.Extensions, NewsDefinitionID)
}

// Victim is the victim/1 property extension of a victim's identity.
type Victim struct {
	ExtensionType string `json:"extension_type"`
	// Countries are ISO 3166-1 alpha-2.
	Countries []string `json:"countries,omitempty"`
	// Domain is canonical, as a Business Context writes its domains.
	Domain string `json:"domain,omitempty"`
}

func NewVictim(v Victim) Victim {
	v.ExtensionType = "property-extension"
	return v
}

// VictimOf is the victim/1 extension of i, and whether i has one.
func VictimOf(i *stix2.Identity) (Victim, bool) {
	return decode[Victim](i.Extensions, VictimDefinitionID)
}

// VictimID is the identity of the victim of a Reported Attack: by its
// canonical domain, or by the Feed's own id for the post when the Feed gives
// no domain, so two posts claiming one domain name one victim.
func VictimID(domain, feed, post string) stix2.Identifier {
	if domain = strings.TrimSpace(domain); domain != "" {
		return ID(stix2.TypeIdentity, "victim:"+domain)
	}
	return ID(stix2.TypeIdentity, "victim:"+feed+":"+post)
}
