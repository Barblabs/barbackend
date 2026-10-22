// Package nvd pulls CVEs modified in the last 24 hours from the NVD API (ADR 0010).
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"barbackend/internal/feeds"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

const (
	defaultURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	pageSize   = 2000
	window     = 24 * time.Hour
	timeLayout = "2006-01-02T15:04:05.000Z07:00"
)

// Adapter fetches and normalizes NVD CVEs.
type Adapter struct {
	Client *http.Client
	URL    string
	APIKey string

	pause time.Duration
}

// New returns an Adapter, defaulting the client and URL and pacing requests by the API key.
func New(client *http.Client, url, apiKey string) *Adapter {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(url) == "" {
		url = defaultURL
	}
	pause := 6 * time.Second
	if apiKey != "" {
		pause = 600 * time.Millisecond
	}
	return &Adapter{Client: client, URL: url, APIKey: apiKey, pause: pause}
}

// Pull fetches every CVE modified in the last 24 hours and emits one Vulnerability per CVE.
func (a *Adapter) Pull(ctx context.Context, emit feeds.Emit) error {
	end := time.Now().UTC()
	start := end.Add(-window)
	for index := 0; ; {
		page, err := a.page(ctx, start, end, index)
		if err != nil {
			return err
		}
		count, err := emitPage(page, emit)
		if err != nil {
			return err
		}
		index += count
		if count == 0 || index >= page.TotalResults {
			return nil
		}
		if err := a.wait(ctx); err != nil {
			return err
		}
	}
}

func emitPage(p page, emit feeds.Emit) (int, error) {
	for _, v := range p.Vulnerabilities {
		obj, ok, err := vulnerability(v.CVE)
		if err != nil {
			return 0, err
		}
		if !ok {
			continue
		}
		if err := emit(obj); err != nil {
			return 0, err
		}
	}
	return len(p.Vulnerabilities), nil
}

func (a *Adapter) page(ctx context.Context, from, to time.Time, index int) (page, error) {
	query := url.Values{}
	query.Set("lastModStartDate", from.Format(timeLayout))
	query.Set("lastModEndDate", to.Format(timeLayout))
	query.Set("startIndex", strconv.Itoa(index))
	query.Set("resultsPerPage", strconv.Itoa(pageSize))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL+"?"+query.Encode(), nil)
	if err != nil {
		return page{}, fmt.Errorf("nvd: %w", err)
	}
	if a.APIKey != "" {
		req.Header.Set("apiKey", a.APIKey)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return page{}, fmt.Errorf("nvd: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return page{}, fmt.Errorf("nvd: %s: %s", a.URL, resp.Status)
	}
	var p page
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return page{}, fmt.Errorf("nvd: decode page %d: %w", index, err)
	}
	return p, nil
}

func (a *Adapter) wait(ctx context.Context) error {
	if a.pause <= 0 {
		return nil
	}
	timer := time.NewTimer(a.pause)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func vulnerability(c cve) (*stix2.Vulnerability, bool, error) {
	id, ok := stixext.CVEID(c.ID)
	if !ok {
		log.Printf("nvd: skipping %q: not a CVE ID", c.ID)
		return nil, false, nil
	}
	published, err := parseTimestamp(c.Published)
	if err != nil {
		return nil, false, fmt.Errorf("nvd: %s: published %q: %w", id, c.Published, err)
	}
	modified, err := parseTimestamp(c.LastModified)
	if err != nil {
		return nil, false, fmt.Errorf("nvd: %s: last modified %q: %w", id, c.LastModified, err)
	}
	refs := make([]*stix2.ExternalReference, 0, len(c.References)+1)
	refs = append(refs, &stix2.ExternalReference{Name: "cve", ExternalID: id})
	for _, r := range c.References {
		refs = append(refs, &stix2.ExternalReference{Name: referenceName(r.Source), URL: r.URL})
	}
	v, err := stix2.NewVulnerability(id,
		stix2.OptionCreatedBy(stixext.BarbattackID),
		stix2.OptionDescription(english(c.Descriptions)),
		stix2.OptionExternalReferences(refs),
		stix2.OptionObjectMarking([]stix2.Identifier{stixext.TLPClear}),
		stix2.OptionExtension(string(stixext.NVDDefinitionID), stixext.NewNVD(stixext.NVD{
			Published:    published.Format(time.RFC3339),
			LastModified: modified.Format(time.RFC3339),
			VulnStatus:   c.VulnStatus,
			CVSS:         cvssMetrics(c.Metrics),
			CWEs:         weaknesses(c.Weaknesses),
			Affected:     affected(c.Configurations),
		})),
	)
	if err != nil {
		return nil, false, fmt.Errorf("nvd: %s: %w", id, err)
	}
	v.ID = stixext.VulnerabilityID(id)
	return v, true, nil
}

func cvssMetrics(m metrics) []stixext.CVSS {
	var out []stixext.CVSS
	for _, group := range [][]metric{m.V2, m.V30, m.V31, m.V40} {
		for _, x := range group {
			out = append(out, stixext.CVSS{
				Version:   x.CVSSData.Version,
				BaseScore: x.CVSSData.BaseScore,
				Vector:    x.CVSSData.VectorString,
				Source:    x.Source,
				Type:      x.Type,
			})
		}
	}
	return out
}

func weaknesses(ws []weakness) []string {
	var out []string
	for _, w := range ws {
		for _, d := range w.Description {
			if d.Lang == "en" {
				out = append(out, d.Value)
			}
		}
	}
	return out
}

func affected(configurations []configuration) []stixext.Affected {
	var out []stixext.Affected
	for _, c := range configurations {
		for _, n := range c.Nodes {
			for _, m := range n.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				vendor, product, ok := cpeVendorProduct(m.Criteria)
				if !ok {
					log.Printf("nvd: skipping CPE %q: not CPE 2.3", m.Criteria)
					continue
				}
				out = append(out, stixext.Affected{
					Criteria:              m.Criteria,
					Vendor:                vendor,
					Product:               product,
					VersionStartIncluding: m.VersionStartIncluding,
					VersionStartExcluding: m.VersionStartExcluding,
					VersionEndIncluding:   m.VersionEndIncluding,
					VersionEndExcluding:   m.VersionEndExcluding,
				})
			}
		}
	}
	return out
}

func cpeVendorProduct(criteria string) (string, string, bool) {
	parts := strings.Split(criteria, ":")
	if len(parts) < 5 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", "", false
	}
	return parts[3], parts[4], true
}

func english(values []langString) string {
	for _, v := range values {
		if v.Lang == "en" {
			return v.Value
		}
	}
	return ""
}

func referenceName(source string) string {
	if source == "" {
		return "nvd"
	}
	return source
}

func parseTimestamp(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("want an RFC 3339 or NVD timestamp")
}

type page struct {
	TotalResults    int    `json:"totalResults"`
	Vulnerabilities []item `json:"vulnerabilities"`
}

type item struct {
	CVE cve `json:"cve"`
}

type cve struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	LastModified   string          `json:"lastModified"`
	VulnStatus     string          `json:"vulnStatus"`
	Descriptions   []langString    `json:"descriptions"`
	Metrics        metrics         `json:"metrics"`
	Weaknesses     []weakness      `json:"weaknesses"`
	Configurations []configuration `json:"configurations"`
	References     []reference     `json:"references"`
}

type langString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metrics struct {
	V2  []metric `json:"cvssMetricV2"`
	V30 []metric `json:"cvssMetricV30"`
	V31 []metric `json:"cvssMetricV31"`
	V40 []metric `json:"cvssMetricV40"`
}

type metric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type weakness struct {
	Description []langString `json:"description"`
}

type configuration struct {
	Nodes []node `json:"nodes"`
}

type node struct {
	CPEMatch []cpeMatch `json:"cpeMatch"`
}

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type reference struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}
