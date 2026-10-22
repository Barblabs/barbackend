package httpapi

import (
	"errors"
	"net/http"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/sources"
	"github.com/gin-gonic/gin"
)

type cmdbSourceHandler struct {
	sources  *sources.Service
	customer inventory.CustomerID
}

// cmdbSourceResponse never carries credentials: a password sent to the
// dashboard could leak from it.
type cmdbSourceResponse struct {
	Provider string `json:"provider"`
	URL      string `json:"url"`
	// User is null for a source that authenticates without one, such as
	// with a token.
	User            *string              `json:"user"`
	LastSync        *time.Time           `json:"lastSync"`
	LastSyncFailure *syncFailureResponse `json:"lastSyncFailure"`
}

type syncFailureResponse struct {
	At    time.Time `json:"at"`
	Error string    `json:"error"`
}

// get answers null rather than 404 when nothing is connected, because that
// is a normal state the dashboard shows the connect flow for.
func (h cmdbSourceHandler) get(ctx *gin.Context) {
	src, err := h.sources.ConnectedSource(ctx, h.customer)
	if errors.Is(err, sources.ErrNotConnected) {
		ctx.JSON(http.StatusOK, nil)
		return
	}
	if err != nil {
		internalError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, newCMDBSourceResponse(src))
}

// loginRequest is the same for every CMDB Provider, so adding one does not
// change the API.
type loginRequest struct {
	Provider string `json:"provider" binding:"required"`
	URL      string `json:"url" binding:"required"`
	User     string `json:"user" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// testResponse carries a failed check with 200, because a CMDB rejecting a
// login is a normal result the dashboard shows inline. Code is stable for
// translation; Error is shown for codes the dashboard does not know.
type testResponse struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

func (h cmdbSourceHandler) test(ctx *gin.Context) {
	var req loginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		badRequest(ctx, err)
		return
	}
	err := h.sources.TestLogin(ctx.Request.Context(), inventory.CMDBProvider(req.Provider), sources.Login{URL: req.URL, User: req.User, Password: req.Password})
	var failure *sources.Failure
	switch {
	case err == nil:
		ctx.JSON(http.StatusOK, testResponse{OK: true})
	case errors.As(err, &failure):
		ctx.JSON(http.StatusOK, testResponse{Code: string(failure.Code), Error: failure.Message})
	case errors.Is(err, sources.ErrInvalidLogin):
		badRequest(ctx, err)
	default:
		internalError(ctx, err)
	}
}

func newCMDBSourceResponse(src sources.ConnectedSource) cmdbSourceResponse {
	resp := cmdbSourceResponse{Provider: string(src.Provider), URL: src.URL}
	if src.User != "" {
		resp.User = &src.User
	}
	if !src.LastSync.IsZero() {
		resp.LastSync = &src.LastSync
	}
	if f := src.LastSyncFailure; f != nil {
		resp.LastSyncFailure = &syncFailureResponse{At: f.At, Error: f.Error}
	}
	return resp
}
