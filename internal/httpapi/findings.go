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
		Description: "One entry per ISO week, in UTC, oldest first and the current week last, with zeros for weeks where nothing happened. opened counts Findings first opened that week; closed counts Findings closed that week. A Finding closed and then reopened keeps no record of that close, so it is not counted as closed.",
		Errors:      []int{http.StatusBadRequest},
	}, h.weeklyTrend)
}

type weeklyTrendQuery struct {
	Weeks trendWeeks `query:"weeks" doc:"How many weeks, the current one included"`
}

type trendWeeks int

func (trendWeeks) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeInteger, Minimum: ptr(1.0), Maximum: ptr(float64(findings.MaxTrendWeeks)), Default: findings.DefaultTrendWeeks}
}

type weeklyTrendResponse struct {
	Weeks []weekResponse `json:"weeks"`
}

type weekResponse struct {
	Week     string `json:"week" doc:"ISO 8601 week, such as 2026-W45"`
	StartsOn string `json:"starts_on" format:"date" doc:"The Monday the week starts on"`
	Opened   int    `json:"opened"`
	Closed   int    `json:"closed"`
}

func (h findingHandler) weeklyTrend(ctx context.Context, caller tenancy.User, in *weeklyTrendQuery) (*body[weeklyTrendResponse], error) {
	weeks, err := h.findings.WeeklyTrend(ctx, caller, int(in.Weeks))
	if err != nil {
		return nil, err
	}
	resp := weeklyTrendResponse{Weeks: make([]weekResponse, len(weeks))}
	for i, w := range weeks {
		year, week := w.Start.ISOWeek()
		resp.Weeks[i] = weekResponse{Week: fmt.Sprintf("%d-W%02d", year, week), StartsOn: w.Start.Format("2006-01-02"), Opened: w.Opened, Closed: w.Closed}
	}
	return &body[weeklyTrendResponse]{Body: resp}, nil
}
