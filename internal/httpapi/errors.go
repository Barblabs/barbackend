package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"barbackend/internal/cmdb"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humagin"
)

type codedError struct {
	status  int
	cause   error
	Code    string `json:"code" doc:"Stable, for the dashboard to translate"`
	Message string `json:"error" doc:"Readable on its own, shown for a code the dashboard does not know"`
}

func (e *codedError) Error() string  { return e.Message }
func (e *codedError) GetStatus() int { return e.status }

const (
	invalidRequest   = "invalid_request"
	invalidLogin     = "invalid_login"
	notConnected     = "not_connected"
	alreadyConnected = "already_connected"
	syncInProgress   = "sync_in_progress"
	syncFailed       = "sync_failed"
	internalError    = "internal_error"
)

func apiError(err error) *codedError {
	var failed *cmdb.SyncError
	if errors.As(err, &failed) {
		return &codedError{status: http.StatusBadGateway, cause: err, Code: failureCode(failed), Message: failed.Error()}
	}
	var failure *cmdb.Failure
	switch {
	case errors.As(err, &failure):
		return &codedError{status: http.StatusUnprocessableEntity, Code: string(failure.Code), Message: failure.Message}
	case errors.Is(err, cmdb.ErrInvalidLogin):
		return &codedError{status: http.StatusBadRequest, Code: invalidLogin, Message: err.Error()}
	case errors.Is(err, cmdb.ErrInvalidAssetQuery):
		return &codedError{status: http.StatusBadRequest, Code: invalidRequest, Message: err.Error()}
	case errors.Is(err, cmdb.ErrNotConnected):
		return &codedError{status: http.StatusNotFound, Code: notConnected, Message: err.Error()}
	case errors.Is(err, cmdb.ErrAlreadyConnected):
		return &codedError{status: http.StatusConflict, Code: alreadyConnected, Message: err.Error()}
	case errors.Is(err, cmdb.ErrSyncInProgress):
		return &codedError{status: http.StatusConflict, Code: syncInProgress, Message: err.Error()}
	default:
		return internal(err)
	}
}

func failureCode(err *cmdb.SyncError) string {
	var failure *cmdb.Failure
	if errors.As(err, &failure) {
		return string(failure.Code)
	}
	return syncFailed
}

func internal(cause error) *codedError {
	return &codedError{status: http.StatusInternalServerError, cause: cause, Code: internalError, Message: "internal server error"}
}

func newHumaError(status int, msg string, errs ...error) huma.StatusError {
	if status >= http.StatusInternalServerError {
		return internal(errors.Join(append([]error{errors.New(msg)}, errs...)...))
	}
	status = schemaFailureAsBadRequest(status)
	details := make([]string, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			details = append(details, errorDetail(err))
		}
	}
	if len(details) > 0 {
		msg = fmt.Sprintf("%s: %s", msg, strings.Join(details, "; "))
	}
	return &codedError{status: status, Code: invalidRequest, Message: msg}
}

// Huma answers a body that fails its schema with 422.
func schemaFailureAsBadRequest(status int) int {
	if status == http.StatusUnprocessableEntity {
		return http.StatusBadRequest
	}
	return status
}

// errorDetail leaves out the value Huma echoes with a detail, which for a
// malformed body is the whole body, password included.
func errorDetail(err error) string {
	var detail *huma.ErrorDetail
	if !errors.As(err, &detail) || detail.Location == "" {
		return err.Error()
	}
	return fmt.Sprintf("%s (%s)", detail.Message, detail.Location)
}

func logCause(ctx huma.Context, _ string, v any) (any, error) {
	if e, ok := v.(*codedError); ok && e.cause != nil {
		_ = humagin.Unwrap(ctx).Error(e.cause)
	}
	return v, nil
}
