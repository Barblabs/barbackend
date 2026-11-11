package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"barbackend/internal/agents"
	"barbackend/internal/areas"
	"barbackend/internal/assets"
	"barbackend/internal/business"
	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
	"barbackend/internal/tenancy"
	"barbackend/internal/users"
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
	invalidRequest      = "invalid_request"
	unauthenticated     = "unauthenticated"
	forbidden           = "forbidden"
	invalidLogin        = "invalid_login"
	notConnected        = "not_connected"
	alreadyConnected    = "already_connected"
	syncInProgress      = "sync_in_progress"
	syncFailed          = "sync_failed"
	customerNotFound    = "customer_not_found"
	customerNameTaken   = "customer_name_taken"
	customerDeactivated = "customer_deactivated"
	emailTaken          = "email_taken"
	userNotFound        = "user_not_found"
	areaNotFound        = "area_not_found"
	lastCustomerAdmin   = "last_customer_admin"
	internalError       = "internal_error"

	prioritizationNotFound = "prioritization_not_found"
	findingNotFound        = "finding_not_found"
	conversationNotFound   = "conversation_not_found"
	conversationBusy       = "conversation_busy"
	conversationFull       = "conversation_full"
	agentRefused           = "agent_refused"
	agentRejected          = "agent_rejected"
	agentUnavailable       = "agent_unavailable"
	invalidDocument        = "invalid_document"
	businessContextStale   = "business_context_stale"
)

func apiError(err error) *codedError {
	var coded *codedError
	if errors.As(err, &coded) {
		return coded
	}
	if e := agentError(err); e != nil {
		return e
	}
	var failed *cmdb.SyncError
	if errors.As(err, &failed) {
		return &codedError{status: http.StatusBadGateway, cause: err, Code: failureCode(failed), Message: failed.Error()}
	}
	var failure *cmdb.Failure
	switch {
	case errors.Is(err, users.ErrUnauthenticated), errors.Is(err, tenancy.ErrUserDisabled):
		return &codedError{status: http.StatusUnauthorized, cause: err, Code: unauthenticated, Message: "a valid access token of a user who can sign in is required"}
	case errors.Is(err, tenancy.ErrNoCustomer):
		return &codedError{status: http.StatusForbidden, Code: forbidden, Message: "a platform admin cannot see customer data"}
	case errors.Is(err, tenancy.ErrNotPlatformAdmin):
		return &codedError{status: http.StatusForbidden, Code: forbidden, Message: "only a platform admin can manage customers"}
	case errors.Is(err, tenancy.ErrNotCustomerAdmin):
		return &codedError{status: http.StatusForbidden, Code: forbidden, Message: "only a customer admin can do this"}
	case errors.Is(err, tenancy.ErrLastCustomerAdmin):
		return &codedError{status: http.StatusConflict, Code: lastCustomerAdmin, Message: "a customer keeps at least one active customer admin"}
	case errors.Is(err, tenancy.ErrCustomerDeactivated):
		return &codedError{status: http.StatusForbidden, Code: customerDeactivated, Message: "your organization's access has been deactivated"}
	case errors.Is(err, tenancy.ErrInvalidCustomer), errors.Is(err, tenancy.ErrInvalidUser):
		return &codedError{status: http.StatusBadRequest, Code: invalidRequest, Message: err.Error()}
	case errors.Is(err, tenancy.ErrCustomerNotFound):
		return &codedError{status: http.StatusNotFound, Code: customerNotFound, Message: "customer not found"}
	case errors.Is(err, tenancy.ErrCustomerNameTaken):
		return &codedError{status: http.StatusConflict, Code: customerNameTaken, Message: "another customer has this name"}
	case errors.Is(err, tenancy.ErrEmailTaken):
		return &codedError{status: http.StatusConflict, Code: emailTaken, Message: "a user with this email already exists"}
	case errors.Is(err, tenancy.ErrUserNotFound):
		return &codedError{status: http.StatusNotFound, Code: userNotFound, Message: "user not found"}
	case errors.As(err, &failure):
		return &codedError{status: http.StatusUnprocessableEntity, Code: string(failure.Code), Message: failure.Message}
	case errors.Is(err, cmdb.ErrInvalidLogin):
		return &codedError{status: http.StatusBadRequest, Code: invalidLogin, Message: err.Error()}
	case errors.Is(err, business.ErrInvalidContext):
		return &codedError{status: http.StatusBadRequest, Code: invalidRequest, Message: err.Error()}
	case errors.Is(err, business.ErrStale):
		return &codedError{status: http.StatusConflict, Code: businessContextStale, Message: business.ErrStale.Error()}
	case errors.Is(err, areas.ErrAreaNotFound):
		return &codedError{status: http.StatusNotFound, Code: areaNotFound, Message: "area not found"}
	case errors.Is(err, assets.ErrInvalidQuery):
		return &codedError{status: http.StatusBadRequest, Code: invalidRequest, Message: err.Error()}
	case errors.Is(err, inventory.ErrNotConnected):
		return &codedError{status: http.StatusNotFound, Code: notConnected, Message: err.Error()}
	case errors.Is(err, inventory.ErrAlreadyConnected):
		return &codedError{status: http.StatusConflict, Code: alreadyConnected, Message: err.Error()}
	case errors.Is(err, inventory.ErrSyncInProgress):
		return &codedError{status: http.StatusConflict, Code: syncInProgress, Message: err.Error()}
	default:
		return internal(err)
	}
}

func agentError(err error) *codedError {
	switch {
	case errors.Is(err, agents.ErrEmptyMessage), errors.Is(err, agents.ErrInvalidFeedback), errors.Is(err, agents.ErrInvalidLimit):
		return &codedError{status: http.StatusBadRequest, Code: invalidRequest, Message: err.Error()}
	case errors.Is(err, agents.ErrInvalidDocument):
		return &codedError{status: http.StatusBadRequest, Code: invalidDocument, Message: err.Error()}
	case errors.Is(err, agents.ErrConversationFull):
		return &codedError{status: http.StatusConflict, Code: conversationFull, Message: agents.ErrConversationFull.Error()}
	case errors.Is(err, agents.ErrPrioritizationNotFound):
		return &codedError{status: http.StatusNotFound, Code: prioritizationNotFound, Message: agents.ErrPrioritizationNotFound.Error()}
	case errors.Is(err, agents.ErrFindingNotFound):
		return &codedError{status: http.StatusNotFound, Code: findingNotFound, Message: agents.ErrFindingNotFound.Error()}
	case errors.Is(err, agents.ErrConversationNotFound):
		return &codedError{status: http.StatusNotFound, Code: conversationNotFound, Message: agents.ErrConversationNotFound.Error()}
	case errors.Is(err, agents.ErrConversationBusy):
		return &codedError{status: http.StatusConflict, Code: conversationBusy, Message: agents.ErrConversationBusy.Error()}
	case errors.Is(err, agents.ErrRefused):
		return &codedError{status: http.StatusBadGateway, cause: err, Code: agentRefused, Message: agents.ErrRefused.Error()}
	case errors.Is(err, agents.ErrRejected):
		return &codedError{status: http.StatusBadGateway, cause: err, Code: agentRejected, Message: agents.ErrRejected.Error()}
	case errors.Is(err, agents.ErrUnavailable):
		return &codedError{status: http.StatusBadGateway, cause: err, Code: agentUnavailable, Message: agents.ErrUnavailable.Error()}
	default:
		return nil
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
