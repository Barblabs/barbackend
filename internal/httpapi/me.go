package httpapi

import (
	"context"
	"net/http"

	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/danielgtaylor/huma/v2"
)

type meHandler struct {
	users *users.Service
}

func (h meHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "get-me",
		Method:      http.MethodGet,
		Path:        "/me",
		Summary:     "The signed-in User's role and Customer",
		Description: "Answered for every role, a Platform Admin included, whose `customer` is null.",
	}, h.get)
}

type meResponse struct {
	ID       string      `json:"id"`
	Email    string      `json:"email"`
	Role     callerRole  `json:"role"`
	Customer *meCustomer `json:"customer"`
}

type meCustomer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// callerRole is any role, unlike roleCode, which lists only the roles a
// Customer Admin can give.
type callerRole string

func (callerRole) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeString, Enum: []any{tenancy.PlatformAdmin.Code(), tenancy.CustomerAdmin.Code(), tenancy.Viewer.Code()}}
}

func (h meHandler) get(ctx context.Context, _ *struct{}) (*body[meResponse], error) {
	caller, err := callerOf(ctx)
	if err != nil {
		return nil, err
	}
	p, err := h.users.Profile(ctx, caller)
	if err != nil {
		return nil, apiError(err)
	}
	resp := meResponse{ID: p.User.ID().String(), Email: p.User.Email(), Role: callerRole(p.User.Role().Code())}
	if p.Customer != (tenancy.Customer{}) {
		resp.Customer = &meCustomer{ID: p.Customer.ID().String(), Name: p.Customer.Name()}
	}
	return &body[meResponse]{Body: resp}, nil
}
