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
		OperationID: "list-customer-stats",
		Method:      http.MethodGet,
		Path:        "/customers/stats",
		Summary:     "Count what every Customer has, by name",
		Description: "Its enabled Users and how its CMDB Source last synced, for a Platform Admin to watch over Customers: never their Assets or Findings.",
	}, h.stats)
	register(api, huma.Operation{
		OperationID: "get-customers-sync-health",
		Method:      http.MethodGet,
		Path:        "/customers/sync-health",
		Summary:     "Count every Customer's Syncs by day",
		Description: "How many Syncs of every Customer's CMDB Source succeeded and failed on each of the last days days, in UTC and today included, oldest first, with zeros for days without a Sync.",
		Errors:      []int{http.StatusBadRequest},
	}, h.syncHealth)
	register(api, huma.Operation{
		OperationID: "get-customers-slack-deliveries",
		Method:      http.MethodGet,
		Path:        "/customers/slack-deliveries",
		Summary:     "Count each Customer's Slack messages by status",
		Description: "How many Slack messages each Customer queued in the last days days, in UTC and today included, were sent, have failed for good and are still pending, by name, every Customer included: never what they say.",
		Errors:      []int{http.StatusBadRequest},
	}, h.slackDeliveries)
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

type customerStatsResponse struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	Active               bool       `json:"active" doc:"False for a Deactivated Customer"`
	UserCount            int        `json:"user_count" doc:"Its Users who are not disabled, those still invited included"`
	CMDBConnected        bool       `json:"cmdb_connected" doc:"Whether it has a connected CMDB Source"`
	CMDBLastSync         *time.Time `json:"cmdb_last_sync" doc:"When the latest successful Sync of its connected CMDB Source finished, null if none succeeded"`
	CMDBLastSyncFailedAt *time.Time `json:"cmdb_last_sync_failed_at" doc:"When its latest Sync finished, set only while that Sync failed"`
}

type customerStatsListResponse struct {
	Customers []customerStatsResponse `json:"customers"`
}

type operationDaysQuery struct {
	Days operationDays `query:"days" doc:"How many days, today included"`
}

type operationDays int

func (operationDays) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeInteger, Minimum: ptr(1.0), Maximum: ptr(float64(users.MaxOperationDays)), Default: users.DefaultOperationDays}
}

type syncHealthResponse struct {
	Days []syncDayResponse `json:"days"`
}

type syncDayResponse struct {
	Date      string `json:"date" format:"date" doc:"The day, in UTC"`
	Succeeded int    `json:"succeeded"`
	Failed    int    `json:"failed"`
}

type slackDeliveriesResponse struct {
	Customers []customerSlackDeliveriesResponse `json:"customers"`
}

type customerSlackDeliveriesResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Sent    int    `json:"sent"`
	Failed  int    `json:"failed" doc:"Failed for good: a Customer Admin can retry them"`
	Pending int    `json:"pending"`
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

func (h customerHandler) create(ctx context.Context, caller tenancy.User, in *body[createCustomerRequest]) (*body[customerResponse], error) {
	return customerOutput(h.users.CreateCustomer(ctx, caller, in.Body.Name, in.Body.AdminEmail))
}

func (h customerHandler) list(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[customerListResponse], error) {
	customers, err := h.users.Customers(ctx, caller)
	if err != nil {
		return nil, err
	}
	resp := customerListResponse{Customers: make([]customerResponse, 0, len(customers))}
	for _, c := range customers {
		resp.Customers = append(resp.Customers, newCustomerResponse(c))
	}
	return &body[customerListResponse]{Body: resp}, nil
}

func (h customerHandler) stats(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[customerStatsListResponse], error) {
	stats, err := h.users.CustomerStats(ctx, caller)
	if err != nil {
		return nil, err
	}
	resp := customerStatsListResponse{Customers: make([]customerStatsResponse, 0, len(stats))}
	for _, s := range stats {
		resp.Customers = append(resp.Customers, customerStatsResponse{
			ID:                   s.Customer.Customer.ID().String(),
			Name:                 s.Customer.Customer.Name(),
			Active:               s.Customer.Deactivated.IsZero(),
			UserCount:            s.Users,
			CMDBConnected:        s.Connected,
			CMDBLastSync:         timeOrNull(s.LastSync),
			CMDBLastSyncFailedAt: timeOrNull(s.LastSyncFailed),
		})
	}
	return &body[customerStatsListResponse]{Body: resp}, nil
}

func (h customerHandler) syncHealth(ctx context.Context, caller tenancy.User, in *operationDaysQuery) (*body[syncHealthResponse], error) {
	days, err := h.users.SyncHealth(ctx, caller, int(in.Days))
	if err != nil {
		return nil, err
	}
	resp := syncHealthResponse{Days: make([]syncDayResponse, len(days))}
	for i, d := range days {
		resp.Days[i] = syncDayResponse{Date: d.Start.Format(time.DateOnly), Succeeded: d.Succeeded, Failed: d.Failed}
	}
	return &body[syncHealthResponse]{Body: resp}, nil
}

func (h customerHandler) slackDeliveries(ctx context.Context, caller tenancy.User, in *operationDaysQuery) (*body[slackDeliveriesResponse], error) {
	counted, err := h.users.SlackDeliveries(ctx, caller, int(in.Days))
	if err != nil {
		return nil, err
	}
	resp := slackDeliveriesResponse{Customers: make([]customerSlackDeliveriesResponse, len(counted))}
	for i, c := range counted {
		resp.Customers[i] = customerSlackDeliveriesResponse{ID: c.Customer.String(), Name: c.Name, Sent: c.Sent, Failed: c.Failed, Pending: c.Pending}
	}
	return &body[slackDeliveriesResponse]{Body: resp}, nil
}

// timeOrNull is null for the zero time, which the domain uses for "never".
func timeOrNull(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (h customerHandler) rename(ctx context.Context, caller tenancy.User, in *renameCustomerInput) (*body[customerResponse], error) {
	return customerOutput(h.users.RenameCustomer(ctx, caller, tenancy.CustomerID(in.ID), in.Body.Name))
}

func (h customerHandler) deactivate(ctx context.Context, caller tenancy.User, in *idPath) (*body[customerResponse], error) {
	return customerOutput(h.users.DeactivateCustomer(ctx, caller, tenancy.CustomerID(in.ID)))
}

func (h customerHandler) reactivate(ctx context.Context, caller tenancy.User, in *idPath) (*body[customerResponse], error) {
	return customerOutput(h.users.ReactivateCustomer(ctx, caller, tenancy.CustomerID(in.ID)))
}

func customerOutput(c users.StoredCustomer, err error) (*body[customerResponse], error) {
	if err != nil {
		return nil, err
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
