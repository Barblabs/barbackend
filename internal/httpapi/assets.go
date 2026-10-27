package httpapi

import (
	"context"
	"net/http"
	"time"

	"barbackend/internal/cmdb"
	"github.com/danielgtaylor/huma/v2"
)

type assetHandler struct {
	cmdb *cmdb.Service
}

func (h assetHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "list-assets",
		Method:      http.MethodGet,
		Path:        "/assets",
		Summary:     "List the Customer's Assets",
		Description: "Pages through Assets in a stable order. Pass next_cursor as cursor, with the same filters, to get the next page.",
		Errors:      []int{http.StatusBadRequest},
	}, h.list)
}

type rawAssetQuery struct {
	Limit       string `query:"limit" doc:"Page size, from 1 to 200; 50 by default"`
	Cursor      string `query:"cursor" doc:"next_cursor of the previous page"`
	Active      string `query:"active" doc:"true (the default), false or all"`
	Kind        string `query:"kind" doc:"Asset Kind code, such as server"`
	Criticality string `query:"criticality" doc:"Criticality code, such as high"`
}

type assetListResponse struct {
	Assets     []assetResponse `json:"assets"`
	NextCursor *string         `json:"next_cursor"`
	Total      int             `json:"total"`
}

type assetResponse struct {
	SourceID      string             `json:"source_id"`
	RecordID      string             `json:"record_id"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Kind          string             `json:"kind"`
	Hardware      *hardwareResponse  `json:"hardware"`
	Software      []softwareResponse `json:"software"`
	Criticality   *string            `json:"criticality"`
	Exposure      *string            `json:"exposure"`
	Owner         *ownerResponse     `json:"owner"`
	Retired       bool               `json:"retired"`
	Active        bool               `json:"active"`
	InactiveSince *time.Time         `json:"inactive_since"`
}

type hardwareResponse struct {
	Vendor string `json:"vendor"`
	Model  string `json:"model"`
}

type softwareResponse struct {
	Role    string           `json:"role"`
	Name    string           `json:"name"`
	Version string           `json:"version"`
	Product *productResponse `json:"product"`
}

type productResponse struct {
	Vendor string `json:"vendor"`
	Name   string `json:"name"`
}

type ownerResponse struct {
	Email  string `json:"email"`
	Source string `json:"source"`
}

func (h assetHandler) list(ctx context.Context, in *rawAssetQuery) (*body[assetListResponse], error) {
	customer, err := customerOf(ctx)
	if err != nil {
		return nil, err
	}
	page, err := h.cmdb.ListAssets(ctx, customer, cmdb.AssetQuery{
		Limit:       in.Limit,
		Cursor:      in.Cursor,
		Active:      in.Active,
		Kind:        in.Kind,
		Criticality: in.Criticality,
	})
	if err != nil {
		return nil, apiError(err)
	}
	return &body[assetListResponse]{Body: newAssetListResponse(page)}, nil
}

func newAssetListResponse(page cmdb.AssetPage) assetListResponse {
	resp := assetListResponse{Assets: make([]assetResponse, len(page.Assets)), Total: page.Total}
	for i, a := range page.Assets {
		resp.Assets[i] = newAssetResponse(a)
	}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	return resp
}

func newAssetResponse(a cmdb.ListedAsset) assetResponse {
	resp := assetResponse{
		SourceID:      a.Ref.Source.String(),
		RecordID:      a.Ref.RecordID,
		Name:          a.Name,
		Description:   a.Description,
		Kind:          a.Kind.Code(),
		Software:      make([]softwareResponse, len(a.Software)),
		Criticality:   code(a.Criticality.Code()),
		Exposure:      code(a.Exposure.Code()),
		Retired:       a.Retired,
		Active:        a.InactiveSince == nil,
		InactiveSince: a.InactiveSince,
	}
	if hw := a.Hardware; hw != nil {
		resp.Hardware = &hardwareResponse{Vendor: hw.Vendor, Model: hw.Model}
	}
	for i, sc := range a.Software {
		resp.Software[i] = softwareResponse{Role: sc.Role.Code(), Name: sc.Name, Version: sc.Version}
		if sc.Identified() {
			resp.Software[i].Product = &productResponse{Vendor: sc.Product.Vendor, Name: sc.Product.Name}
		}
	}
	if o := a.Owner; o != nil {
		resp.Owner = &ownerResponse{Email: o.Email.String(), Source: "imported"}
		if o.Declared {
			resp.Owner.Source = "declared"
		}
	}
	return resp
}

func code(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
