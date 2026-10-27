package httpapi

import (
	"context"
	"net/http"
	"time"

	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

type customerHandler struct {
	users *users.Service
}

func (h customerHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID:   "create-customer",
		Method:        http.MethodPost,
		Path:          "/customers",
		Summary:       "Create a Customer and invite its first Customer Admin",
		DefaultStatus: http.StatusCreated,
		Errors:        []int{http.StatusBadRequest, http.StatusConflict},
	}, h.create)
	register(api, huma.Operation{
		OperationID: "list-customers",
		Method:      http.MethodGet,
		Path:        "/customers",
		Summary:     "List every Customer, by name",
	}, h.list)
	register(api, huma.Operation{
		OperationID: "rename-customer",
		Method:      http.MethodPatch,
		Path:        "/customers/{id}",
		Summary:     "Rename a Customer",
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict},
	}, h.rename)
	register(api, huma.Operation{
		OperationID: "deactivate-customer",
		Method:      http.MethodPost,
		Path:        "/customers/{id}/deactivate",
		Summary:     "Deactivate a Customer",
		Description: "Its Users can no longer sign in and its CMDB Source is no longer synced. Deactivating a Deactivated Customer changes nothing.",
		Errors:      []int{http.StatusNotFound},
	}, h.deactivate)
	register(api, huma.Operation{
		OperationID: "reactivate-customer",
		Method:      http.MethodPost,
		Path:        "/customers/{id}/reactivate",
		Summary:     "Reactivate a Deactivated Customer",
		Description: "Its Users can sign in again and its CMDB Source is synced again, as before it was deactivated.",
		Errors:      []int{http.StatusNotFound},
	}, h.reactivate)
}

type customerResponse struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	CreatedAt     time.Time  `json:"created_at"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
}

type customerListResponse struct {
	Customers []customerResponse `json:"customers"`
}

type createCustomerRequest struct {
	_          struct{} `additionalProperties:"true"`
	Name       string   `json:"name" minLength:"1"`
	AdminEmail string   `json:"admin_email" format:"email" doc:"Invited by Cognito as the Customer's first Customer Admin"`
}

type renameCustomerRequest struct {
	_    struct{} `additionalProperties:"true"`
	Name string   `json:"name" minLength:"1"`
}

type renameCustomerInput struct {
	ID   uuid.UUID `path:"id" format:"uuid"`
	Body renameCustomerRequest
}

func (h customerHandler) create(ctx context.Context, in *body[createCustomerRequest]) (*body[customerResponse], error) {
	caller, err := callerOf(ctx)
	if err != nil {
		return nil, err
	}
	return customerOutput(h.users.CreateCustomer(ctx, caller, in.Body.Name, in.Body.AdminEmail))
}

func (h customerHandler) list(ctx context.Context, _ *struct{}) (*body[customerListResponse], error) {
	caller, err := callerOf(ctx)
	if err != nil {
		return nil, err
	}
	customers, err := h.users.Customers(ctx, caller)
	if err != nil {
		return nil, apiError(err)
	}
	resp := customerListResponse{Customers: make([]customerResponse, 0, len(customers))}
	for _, c := range customers {
		resp.Customers = append(resp.Customers, newCustomerResponse(c))
	}
	return &body[customerListResponse]{Body: resp}, nil
}

func (h customerHandler) rename(ctx context.Context, in *renameCustomerInput) (*body[customerResponse], error) {
	caller, err := callerOf(ctx)
	if err != nil {
		return nil, err
	}
	return customerOutput(h.users.RenameCustomer(ctx, caller, tenancy.CustomerID(in.ID), in.Body.Name))
}

func (h customerHandler) deactivate(ctx context.Context, in *idPath) (*body[customerResponse], error) {
	caller, err := callerOf(ctx)
	if err != nil {
		return nil, err
	}
	return customerOutput(h.users.DeactivateCustomer(ctx, caller, tenancy.CustomerID(in.ID)))
}

func (h customerHandler) reactivate(ctx context.Context, in *idPath) (*body[customerResponse], error) {
	caller, err := callerOf(ctx)
	if err != nil {
		return nil, err
	}
	return customerOutput(h.users.ReactivateCustomer(ctx, caller, tenancy.CustomerID(in.ID)))
}

func customerOutput(c users.StoredCustomer, err error) (*body[customerResponse], error) {
	if err != nil {
		return nil, apiError(err)
	}
	return &body[customerResponse]{Body: newCustomerResponse(c)}, nil
}

func newCustomerResponse(c users.StoredCustomer) customerResponse {
	resp := customerResponse{ID: c.Customer.ID().String(), Name: c.Customer.Name(), CreatedAt: c.Created}
	if !c.Deactivated.IsZero() {
		resp.DeactivatedAt = &c.Deactivated
	}
	return resp
}
