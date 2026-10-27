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

type userHandler struct {
	users *users.Service
}

func (h userHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "list-users",
		Method:      http.MethodGet,
		Path:        "/users",
		Summary:     "List the Users of the caller's Customer, by email",
		Description: "Disabled Users are listed too: Users are never deleted.",
	}, h.list)
	register(api, huma.Operation{
		OperationID:   "invite-user",
		Method:        http.MethodPost,
		Path:          "/users",
		Summary:       "Invite a User of the caller's Customer",
		DefaultStatus: http.StatusCreated,
		Errors:        []int{http.StatusBadRequest, http.StatusConflict},
	}, h.invite)
	register(api, huma.Operation{
		OperationID: "change-user-role",
		Method:      http.MethodPatch,
		Path:        "/users/{id}",
		Summary:     "Change the role of a User of the caller's Customer",
		Description: "Demoting the Customer's last active Customer Admin is refused.",
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict},
	}, h.changeRole)
	register(api, huma.Operation{
		OperationID: "disable-user",
		Method:      http.MethodPost,
		Path:        "/users/{id}/disable",
		Summary:     "Disable a User of the caller's Customer",
		Description: "They can no longer sign in. Disabling the Customer's last active Customer Admin is refused.",
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict},
	}, h.disable)
}

type userResponse struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	Role       string     `json:"role" enum:"customer_admin,viewer"`
	CreatedAt  time.Time  `json:"created_at"`
	DisabledAt *time.Time `json:"disabled_at"`
}

type userListResponse struct {
	Users []userResponse `json:"users"`
}

type inviteUserRequest struct {
	_     struct{} `additionalProperties:"true"`
	Email string   `json:"email" format:"email" doc:"Invited by Cognito"`
	Role  string   `json:"role" enum:"customer_admin,viewer"`
}

type changeRoleRequest struct {
	_    struct{} `additionalProperties:"true"`
	Role string   `json:"role" enum:"customer_admin,viewer"`
}

type userPath struct {
	ID uuid.UUID `path:"id" format:"uuid"`
}

type changeRoleInput struct {
	ID   uuid.UUID `path:"id" format:"uuid"`
	Body changeRoleRequest
}

func (h userHandler) list(ctx context.Context, _ *struct{}) (*body[userListResponse], error) {
	caller, err := callerOf(ctx)
	if err != nil {
		return nil, err
	}
	stored, err := h.users.Users(ctx, caller)
	if err != nil {
		return nil, apiError(err)
	}
	resp := userListResponse{Users: make([]userResponse, 0, len(stored))}
	for _, u := range stored {
		resp.Users = append(resp.Users, newUserResponse(u))
	}
	return &body[userListResponse]{Body: resp}, nil
}

func (h userHandler) invite(ctx context.Context, in *body[inviteUserRequest]) (*body[userResponse], error) {
	caller, err := callerOf(ctx)
	if err != nil {
		return nil, err
	}
	role, err := tenancy.ParseRole(in.Body.Role)
	if err != nil {
		return nil, apiError(err)
	}
	return userOutput(h.users.InviteUser(ctx, caller, in.Body.Email, role))
}

func (h userHandler) changeRole(ctx context.Context, in *changeRoleInput) (*body[userResponse], error) {
	caller, err := callerOf(ctx)
	if err != nil {
		return nil, err
	}
	role, err := tenancy.ParseRole(in.Body.Role)
	if err != nil {
		return nil, apiError(err)
	}
	return userOutput(h.users.ChangeRole(ctx, caller, tenancy.UserID(in.ID), role))
}

func (h userHandler) disable(ctx context.Context, in *userPath) (*body[userResponse], error) {
	caller, err := callerOf(ctx)
	if err != nil {
		return nil, err
	}
	return userOutput(h.users.DisableUser(ctx, caller, tenancy.UserID(in.ID)))
}

func userOutput(u users.StoredUser, err error) (*body[userResponse], error) {
	if err != nil {
		return nil, apiError(err)
	}
	return &body[userResponse]{Body: newUserResponse(u)}, nil
}

func newUserResponse(u users.StoredUser) userResponse {
	resp := userResponse{ID: u.User.ID().String(), Email: u.User.Email(), Role: u.User.Role().Code(), CreatedAt: u.Created}
	if !u.Disabled.IsZero() {
		resp.DisabledAt = &u.Disabled
	}
	return resp
}
