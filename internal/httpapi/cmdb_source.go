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
	Provider        string               `json:"provider"`
	URL             string               `json:"url"`
	User            string               `json:"user"`
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

func newCMDBSourceResponse(src sources.ConnectedSource) cmdbSourceResponse {
	resp := cmdbSourceResponse{Provider: string(src.Provider), URL: src.URL, User: src.User}
	if !src.LastSync.IsZero() {
		resp.LastSync = &src.LastSync
	}
	if f := src.LastSyncFailure; f != nil {
		resp.LastSyncFailure = &syncFailureResponse{At: f.At, Error: f.Error}
	}
	return resp
}
