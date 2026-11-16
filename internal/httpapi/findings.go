package httpapi

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"strconv"

	"barbackend/internal/findings"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
)

type findingHandler struct {
	findings *findings.Service
}

func (h findingHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "get-findings-weekly-trend",
		Method:      http.MethodGet,
		Path:        "/findings/weekly-trend",
		Summary:     "Count the Customer's Findings opened and closed each week",
		Description: "One entry per ISO week, in UTC, oldest first and the current week last, with zeros for weeks where nothing happened. opened counts Findings first opened that week; closed counts Findings closed that week; open_at_end counts those still open when it ended. A Finding closed and then reopened keeps no record of that close, so it is not counted as closed, and counts as open while it was closed.",
		Errors:      []int{http.StatusBadRequest},
	}, h.weeklyTrend)
	register(api, huma.Operation{
		OperationID: "get-findings-summary",
		Method:      http.MethodGet,
		Path:        "/findings/summary",
		Summary:     "Count the Customer's open Findings at a glance",
		Description: "Its open scored Findings by the Score Band of their latest Score, how many of them KEV lists, and how many are Critical on Internet-facing Assets. A Finding not scored yet is left out.",
	}, h.summary)
	register(api, huma.Operation{
		OperationID: "get-findings-breakdown",
		Method:      http.MethodGet,
		Path:        "/findings/breakdown",
		Summary:     "Count the Customer's open Findings by Score Band within each Exposure, Criticality or Area",
		Description: "By exposure (the effective one) and by criticality every value is there, unknown last, so a heatmap keeps its columns. By area only the Areas with open Findings are, by name, then none for the Assets in no Area. Each Finding is counted in one group. A Finding not scored yet is left out.",
		Errors:      []int{http.StatusBadRequest},
	}, h.breakdown)
	register(api, huma.Operation{
		OperationID: "get-findings-top",
		Method:      http.MethodGet,
		Path:        "/findings/top",
		Summary:     "List the components and CVEs with the most severe open Findings",
		Description: "Each list is ordered by its open Findings' Score Bands, most Critical first, then by how many it has. A component is a Product at one version, so updating it closes its Findings. A Finding not scored yet is left out.",
		Errors:      []int{http.StatusBadRequest},
	}, h.top)
	register(api, huma.Operation{
		OperationID: "get-findings-attack-matrix",
		Method:      http.MethodGet,
		Path:        "/findings/attack-matrix",
		Summary:     "Count the Customer's open Findings by ATT&CK tactic and Technique",
		Description: "The Cartógrafo labels a CVE with up to 5 ATT&CK Techniques, each exploiting it, its primary impact or a secondary impact; a Finding has the labels of its CVE. These labels are inferred by a model and must be shown as such. Every tactic of the stored catalog is there, in attack order; a Finding counts once in each tactic and each Technique it has, so the tactics do not add up to the Findings: coverage tells how many Findings have a labeled CVE. With role, only the labels of that role count, but coverage does not change. A Finding not scored yet is left out.",
		Errors:      []int{http.StatusBadRequest},
	}, h.attackMatrix)
}

type weeklyTrendQuery struct {
	Weeks trendWeeks `query:"weeks" doc:"How many weeks, the current one included"`
}

type trendWeeks int

func (trendWeeks) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeInteger, Minimum: ptr(1.0), Maximum: ptr(float64(findings.MaxTrendWeeks)), Default: findings.DefaultTrendWeeks}
}

type bandCountsResponse struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unbanded int `json:"unbanded" doc:"Open Findings whose latest Score is from a Scoring Model before 3, which has no Score Bands; they get one when rescored"`
}

func newBandCounts(c findings.BandCounts) bandCountsResponse {
	return bandCountsResponse{Critical: c.Critical, High: c.High, Medium: c.Medium, Low: c.Low, Unbanded: c.Unbanded}
}

type findingsSummaryResponse struct {
	Open int `json:"open"`
	bandCountsResponse
	KEV                    int `json:"kev" doc:"Open Findings whose CVE KEV lists"`
	CriticalInternetFacing int `json:"critical_internet_facing" doc:"Critical open Findings on Internet-facing Assets"`
}

func (h findingHandler) summary(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[findingsSummaryResponse], error) {
	sum, err := h.findings.Summary(ctx, caller)
	if err != nil {
		return nil, err
	}
	return &body[findingsSummaryResponse]{Body: findingsSummaryResponse{
		Open: sum.Bands.Total(), bandCountsResponse: newBandCounts(sum.Bands), KEV: sum.KEV, CriticalInternetFacing: sum.CriticalInternetFacing,
	}}, nil
}

type breakdownQuery struct {
	By string `query:"by" enum:"exposure,criticality,area" default:"exposure"`
}

var groupings = map[string]findings.Grouping{"exposure": findings.ByExposure, "criticality": findings.ByCriticality, "area": findings.ByArea}

type breakdownResponse struct {
	By     string          `json:"by"`
	Groups []groupResponse `json:"groups"`
}

type groupResponse struct {
	Value string  `json:"value" doc:"The exposure or criticality code, unknown, the Area's id as in GET /areas, or none for the Assets in no Area"`
	Name  *string `json:"name" doc:"The Area's name when grouped by area, null otherwise"`
	bandCountsResponse
}

func (h findingHandler) breakdown(ctx context.Context, caller tenancy.User, in *breakdownQuery) (*body[breakdownResponse], error) {
	groups, err := h.findings.Breakdown(ctx, caller, groupings[in.By])
	if err != nil {
		return nil, err
	}
	resp := breakdownResponse{By: in.By, Groups: make([]groupResponse, len(groups))}
	for i, g := range groups {
		group := groupResponse{bandCountsResponse: newBandCounts(g.Bands)}
		switch in.By {
		case "exposure":
			group.Value = cmp.Or(g.Exposure.Code(), unknownFilterCode)
		case "criticality":
			group.Value = cmp.Or(g.Criticality.Code(), unknownFilterCode)
		default:
			group.Value = "none"
			if g.Area != nil {
				group.Value, group.Name = strconv.FormatInt(g.Area.ID, 10), &g.Area.Name
			}
		}
		resp.Groups[i] = group
	}
	return &body[breakdownResponse]{Body: resp}, nil
}

type topQuery struct {
	Limit topLimit `query:"limit" doc:"How many of each list"`
}

type topLimit int

func (topLimit) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeInteger, Minimum: ptr(1.0), Maximum: ptr(float64(findings.MaxTopLimit)), Default: findings.DefaultTopLimit}
}

type topResponse struct {
	Components []componentCountResponse `json:"components"`
	CVEs       []cveCountResponse       `json:"cves"`
}

type componentCountResponse struct {
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Version  string `json:"version"`
	Findings int    `json:"findings"`
	Assets   int    `json:"assets" doc:"Assets running it with an open Finding"`
	bandCountsResponse
}

type cveCountResponse struct {
	CVEID    string   `json:"cve_id"`
	KEV      bool     `json:"kev"`
	EPSS     *float64 `json:"epss" doc:"EPSS probability, null when EPSS has no score for the CVE yet"`
	Findings int      `json:"findings"`
	Assets   int      `json:"assets"`
	bandCountsResponse
}

func (h findingHandler) top(ctx context.Context, caller tenancy.User, in *topQuery) (*body[topResponse], error) {
	top, err := h.findings.Top(ctx, caller, int(in.Limit))
	if err != nil {
		return nil, err
	}
	resp := topResponse{Components: make([]componentCountResponse, len(top.Components)), CVEs: make([]cveCountResponse, len(top.CVEs))}
	for i, c := range top.Components {
		resp.Components[i] = componentCountResponse{Vendor: c.Product.Vendor, Product: c.Product.Name, Version: c.Version, Findings: c.Bands.Total(), Assets: c.Assets, bandCountsResponse: newBandCounts(c.Bands)}
	}
	for i, c := range top.CVEs {
		resp.CVEs[i] = cveCountResponse{CVEID: c.CVE, KEV: c.KEV, EPSS: c.EPSS, Findings: c.Bands.Total(), Assets: c.Assets, bandCountsResponse: newBandCounts(c.Bands)}
	}
	return &body[topResponse]{Body: resp}, nil
}

type attackMatrixQuery struct {
	Role  string   `query:"role" enum:"exploitation,primary_impact,secondary_impact" doc:"Count only the labels of this role"`
	Limit topLimit `query:"limit" doc:"How many Techniques"`
}

type attackMatrixResponse struct {
	Coverage   coverageResponse         `json:"coverage"`
	Tactics    []tacticCountResponse    `json:"tactics"`
	Techniques []techniqueCountResponse `json:"techniques" doc:"Those with the most open Findings, most first"`
}

type coverageResponse struct {
	Labeled int `json:"labeled" doc:"Open Findings whose CVE has a label, whatever its role"`
	Open    int `json:"open"`
}

type tacticCountResponse struct {
	Tactic string `json:"tactic" doc:"ATT&CK tactic short name, such as initial-access"`
	bandCountsResponse
}

type techniqueCountResponse struct {
	AttackID string   `json:"attack_id"`
	Name     string   `json:"name"`
	Tactics  []string `json:"tactics"`
	Roles    []string `json:"roles" doc:"The roles it is labeled with on these Findings' CVEs"`
	Findings int      `json:"findings"`
	bandCountsResponse
}

func (h findingHandler) attackMatrix(ctx context.Context, caller tenancy.User, in *attackMatrixQuery) (*body[attackMatrixResponse], error) {
	m, err := h.findings.AttackMatrix(ctx, caller, in.Role, int(in.Limit))
	if err != nil {
		return nil, err
	}
	resp := attackMatrixResponse{
		Coverage:   coverageResponse{Labeled: m.Labeled, Open: m.Open},
		Tactics:    make([]tacticCountResponse, len(m.Tactics)),
		Techniques: make([]techniqueCountResponse, len(m.Techniques)),
	}
	for i, t := range m.Tactics {
		resp.Tactics[i] = tacticCountResponse{Tactic: t.Tactic, bandCountsResponse: newBandCounts(t.Bands)}
	}
	for i, t := range m.Techniques {
		resp.Techniques[i] = techniqueCountResponse{AttackID: t.AttackID, Name: t.Name, Tactics: t.Tactics, Roles: t.Roles, Findings: t.Bands.Total(), bandCountsResponse: newBandCounts(t.Bands)}
	}
	return &body[attackMatrixResponse]{Body: resp}, nil
}

type weeklyTrendResponse struct {
	Weeks []weekResponse `json:"weeks"`
}

type weekResponse struct {
	Week     string `json:"week" doc:"ISO 8601 week, such as 2026-W45"`
	StartsOn string `json:"starts_on" format:"date" doc:"The Monday the week starts on"`
	Opened   int    `json:"opened"`
	Closed   int    `json:"closed"`
	OpenAt   int    `json:"open_at_end" doc:"Findings open when the week ended, or open now for the current week: the backlog"`
}

func (h findingHandler) weeklyTrend(ctx context.Context, caller tenancy.User, in *weeklyTrendQuery) (*body[weeklyTrendResponse], error) {
	weeks, err := h.findings.WeeklyTrend(ctx, caller, int(in.Weeks))
	if err != nil {
		return nil, err
	}
	resp := weeklyTrendResponse{Weeks: make([]weekResponse, len(weeks))}
	for i, w := range weeks {
		year, week := w.Start.ISOWeek()
		resp.Weeks[i] = weekResponse{Week: fmt.Sprintf("%d-W%02d", year, week), StartsOn: w.Start.Format("2006-01-02"), Opened: w.Opened, Closed: w.Closed, OpenAt: w.OpenAtEnd}
	}
	return &body[weeklyTrendResponse]{Body: resp}, nil
}
