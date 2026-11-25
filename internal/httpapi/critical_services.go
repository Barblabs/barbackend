package httpapi

import (
	"context"
	"net/http"

	"barbackend/internal/businesscontext"
	"barbackend/internal/findings"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
)

type criticalServiceHandler struct {
	contexts *businesscontext.Service
	findings *findings.Service
}

func (h criticalServiceHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "get-critical-services",
		Method:      http.MethodGet,
		Path:        "/critical-services",
		Summary:     "Report how each Critical Service is doing with the open Findings of its Assets",
		Description: "One entry per Critical Service of the latest Business Context, in its order; none without a Business Context. A listed Asset name matches every Active Asset with the same name once both are trimmed, ignoring case, and a Finding on an Asset matched twice counts once. status is at_risk when an open Critical Finding is in CISA KEV or in the news, otherwise watch when any open Finding is Critical, otherwise clear. A Finding is in the news when a News Item published in the last 7 days names its CVE. The list is not paged.",
	}, h.list)
}

type criticalServiceHealthListResponse struct {
	CriticalServices []criticalServiceHealthResponse `json:"critical_services"`
}

type criticalServiceHealthResponse struct {
	Name               string   `json:"name"`
	Status             string   `json:"status" enum:"at_risk,watch,clear"`
	CriticalOpen       int      `json:"critical_open" doc:"Open Findings on its Assets whose latest Score is Critical"`
	HighOpen           int      `json:"high_open" doc:"Open Findings on its Assets whose latest Score is High"`
	InTheNews          int      `json:"in_the_news" doc:"Open Critical Findings on its Assets whose CVE a News Item published in the last 7 days names"`
	OldestCriticalDays *int     `json:"oldest_critical_days" doc:"As in GET /areas/health; null when none is Critical"`
	UnmatchedAssets    []string `json:"unmatched_assets" doc:"The Asset names that match no Active Asset, as the Business Context states them"`
}

func (h criticalServiceHandler) list(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[criticalServiceHealthListResponse], error) {
	stored, err := h.contexts.Get(ctx, caller)
	if err != nil {
		return nil, err
	}
	health, err := h.findings.CriticalServiceHealth(ctx, caller, stored.Context.Fields().Operations.CriticalServices)
	if err != nil {
		return nil, err
	}
	resp := criticalServiceHealthListResponse{CriticalServices: make([]criticalServiceHealthResponse, len(health))}
	for i, s := range health {
		resp.CriticalServices[i] = criticalServiceHealthResponse{
			Name: s.Name, Status: s.Status.String(),
			CriticalOpen: s.Open.Critical, HighOpen: s.Open.High, InTheNews: s.InTheNews,
			OldestCriticalDays: s.OldestCriticalDays, UnmatchedAssets: s.UnmatchedAssets,
		}
	}
	return &body[criticalServiceHealthListResponse]{Body: resp}, nil
}
