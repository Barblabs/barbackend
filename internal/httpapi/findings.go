package httpapi

import (
	"context"
	"fmt"
	"net/http"

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
		Description: "One entry per ISO week, in UTC, oldest first and the current week last, with zeros for weeks where nothing happened. opened counts Findings first opened that week; closed counts Findings closed that week; open_at_end counts those still open when it ended; critical_open_at_end counts those of them whose latest Score by then was in the Critical Band, so for the current week it is critical of /findings/summary. A Finding closed and then reopened keeps no record of that close, so it is not counted as closed, and counts as open while it was closed.",
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
		OperationID: "get-findings-attack-matrix",
		Method:      http.MethodGet,
		Path:        "/findings/attack-matrix",
		Summary:     "Count the Customer's open Findings by ATT&CK tactic and Technique",
		Description: "The Cartógrafo labels a CVE with up to 5 ATT&CK Techniques, each exploiting it, its primary impact or a secondary impact; a Finding has the labels of its CVE. These labels are inferred by a model and must be shown as such. Every tactic of the stored catalog is there, in attack order; a Finding counts once in each tactic and each Technique it has, so the tactics do not add up to the Findings: coverage tells how many Findings have a labeled CVE. With role, only the labels of that role count, but coverage does not change. A Finding not scored yet is left out.",
		Errors:      []int{http.StatusBadRequest},
	}, h.attackMatrix)
	register(api, huma.Operation{
		OperationID: "get-findings-closes",
		Method:      http.MethodGet,
		Path:        "/findings/closes",
		Summary:     "Count the Customer's Findings closed as Fixed, Went away and Set aside",
		Description: "For the last days days ending now, and for the days days before that: Findings first opened, so a reopen is not new, and Findings closed by bucket. fixed is remediated, component_removed and no_longer_affected; went_away is asset_inactive, vulnerability_rejected and vulnerability_revised; set_aside is accepted_risk, postponed and false_positive. The buckets are never added together. A Finding closed and then reopened keeps no record of that close, so it is not counted as closed.",
		Errors:      []int{http.StatusBadRequest},
	}, h.closes)
	h.registerCloses(api)
}

type weeklyTrendQuery struct {
	Weeks trendWeeks `query:"weeks" doc:"How many weeks, the current one included"`
}

type trendWeeks int

func (trendWeeks) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeInteger, Minimum: ptr(1.0), Maximum: ptr(float64(findings.MaxTrendWeeks)), Default: findings.DefaultTrendWeeks}
}

type closesQuery struct {
	Days closesDays `query:"days" doc:"How many days each window lasts"`
}

type closesDays int

func (closesDays) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeInteger, Minimum: ptr(1.0), Maximum: ptr(float64(findings.MaxClosesDays)), Default: findings.DefaultClosesDays}
}

type closesResponse struct {
	Current                 closeCountsResponse `json:"current" doc:"The last days days, ending now"`
	Previous                closeCountsResponse `json:"previous" doc:"The days days before current"`
	CriticalFixedMedianDays *float64            `json:"critical_fixed_median_days" doc:"Median days from opening to closing of the Fixed Findings of current whose latest Score is Critical; null when there are none"`
}

type closeCountsResponse struct {
	Opened   int `json:"opened" doc:"Findings first opened"`
	Fixed    int `json:"fixed"`
	WentAway int `json:"went_away"`
	SetAside int `json:"set_aside"`
}

func newCloseCounts(c findings.CloseCounts) closeCountsResponse {
	return closeCountsResponse{Opened: c.Opened, Fixed: c.Fixed, WentAway: c.WentAway, SetAside: c.SetAside}
}

func (h findingHandler) closes(ctx context.Context, caller tenancy.User, in *closesQuery) (*body[closesResponse], error) {
	c, err := h.findings.Closes(ctx, caller, int(in.Days))
	if err != nil {
		return nil, err
	}
	return &body[closesResponse]{Body: closesResponse{
		Current: newCloseCounts(c.Current), Previous: newCloseCounts(c.Previous), CriticalFixedMedianDays: c.CriticalFixedMedianDays,
	}}, nil
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

type topLimit int

func (topLimit) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeInteger, Minimum: ptr(1.0), Maximum: ptr(float64(findings.MaxTopLimit)), Default: findings.DefaultTopLimit}
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
	Critical int    `json:"critical_open_at_end" doc:"Findings open when the week ended whose latest Score by then was Critical, or open and Critical now for the current week"`
}

func (h findingHandler) weeklyTrend(ctx context.Context, caller tenancy.User, in *weeklyTrendQuery) (*body[weeklyTrendResponse], error) {
	weeks, err := h.findings.WeeklyTrend(ctx, caller, int(in.Weeks))
	if err != nil {
		return nil, err
	}
	resp := weeklyTrendResponse{Weeks: make([]weekResponse, len(weeks))}
	for i, w := range weeks {
		year, week := w.Start.ISOWeek()
		resp.Weeks[i] = weekResponse{Week: fmt.Sprintf("%d-W%02d", year, week), StartsOn: w.Start.Format("2006-01-02"), Opened: w.Opened, Closed: w.Closed, OpenAt: w.OpenAtEnd, Critical: w.CriticalOpenAtEnd}
	}
	return &body[weeklyTrendResponse]{Body: resp}, nil
}
