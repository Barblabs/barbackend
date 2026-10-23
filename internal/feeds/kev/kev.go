package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"barbackend/internal/feeds"
	"barbackend/internal/feeds/httpx"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

const (
	defaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	dateLayout = "2006-01-02"
)

type Adapter struct {
	httpx.Endpoint
}

// New returns an Adapter, defaulting the client and URL when they are empty.
func New(client *http.Client, url string) *Adapter {
	return &Adapter{Endpoint: httpx.NewEndpoint(client, url, defaultURL)}
}

// Pull fetches the catalog and emits one Vulnerability per entry.
func (a *Adapter) Pull(ctx context.Context, emit feeds.Emit) error {
	c, err := a.fetch(ctx)
	if err != nil {
		return err
	}
	released, err := time.Parse(time.RFC3339, c.DateReleased)
	if err != nil {
		return fmt.Errorf("kev: catalog date released %q: %w", c.DateReleased, err)
	}
	for _, e := range c.Vulnerabilities {
		v, ok, err := vulnerability(e, c.CatalogVersion, released)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := emit(v); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) fetch(ctx context.Context) (catalog, error) {
	resp, err := a.Get(ctx, "kev")
	if err != nil {
		return catalog{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var c catalog
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return catalog{}, fmt.Errorf("kev: decode catalog: %w", err)
	}
	return c, nil
}

func vulnerability(e entry, catalogVersion string, released time.Time) (*stix2.Vulnerability, bool, error) {
	id, ok := stixext.CVEID(e.CVEID)
	if !ok {
		log.Printf("kev: skipping %q: not a CVE ID", e.CVEID)
		return nil, false, nil
	}
	added, err := time.Parse(dateLayout, e.DateAdded)
	if err != nil {
		return nil, false, fmt.Errorf("kev: %s: date added %q: %w", id, e.DateAdded, err)
	}
	due, err := time.Parse(dateLayout, e.DueDate)
	if err != nil {
		return nil, false, fmt.Errorf("kev: %s: due date %q: %w", id, e.DueDate, err)
	}
	v, err := stix2.NewVulnerability(id,
		stix2.OptionCreatedBy(stixext.BarbattackID),
		stix2.OptionDescription(e.ShortDescription),
		stix2.OptionExternalReferences([]*stix2.ExternalReference{{Name: "cve", ExternalID: id}}),
		stix2.OptionObjectMarking([]stix2.Identifier{stixext.TLPClear}),
		stix2.OptionExtension(string(stixext.KEVDefinitionID), stixext.NewKEV(stixext.KEV{
			DateAdded:                  added.Format(dateLayout),
			DueDate:                    due.Format(dateLayout),
			RequiredAction:             e.RequiredAction,
			KnownRansomwareCampaignUse: e.KnownRansomwareCampaignUse,
			VendorProject:              e.VendorProject,
			Product:                    e.Product,
			CatalogVersion:             catalogVersion,
			CatalogReleased:            released.UTC().Format(time.RFC3339),
		})),
	)
	if err != nil {
		return nil, false, fmt.Errorf("kev: %s: %w", id, err)
	}
	v.ID = stixext.VulnerabilityID(id)
	return v, true, nil
}

type catalog struct {
	CatalogVersion  string  `json:"catalogVersion"`
	DateReleased    string  `json:"dateReleased"`
	Vulnerabilities []entry `json:"vulnerabilities"`
}

type entry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}
