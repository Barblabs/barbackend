// Package httpapi is the HTTP transport: it routes requests to use cases
// (ADR 0008).
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humagin"
	"github.com/gin-gonic/gin"
)

type Config struct {
	CMDB *cmdb.Service
	// Customer is who every request acts for. It comes from server
	// configuration until authentication exists.
	Customer inventory.CustomerID
	// AllowedOrigins may call the API from a browser.
	AllowedOrigins []string
}

func New(cfg Config) http.Handler {
	router := gin.Default()
	router.Use(cors(cfg.AllowedOrigins))
	router.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	api := humagin.New(router, apiConfig())
	cmdbSourceHandler{cmdb: cfg.CMDB, customer: cfg.Customer}.register(api)
	assetHandler{cmdb: cfg.CMDB, customer: cfg.Customer}.register(api)
	return router
}

// apiConfig serves the spec at /openapi.json and /openapi.yaml and the docs
// UI at /docs.
func apiConfig() huma.Config {
	config := huma.DefaultConfig("barbattack", "1.0.0")
	// The default hook adds a $schema field to every response body, which
	// would change the wire format.
	config.CreateHooks = nil
	config.Formats = map[string]huma.Format{"application/json": jsonFormat, "json": jsonFormat}
	config.Transformers = []huma.Transformer{logCause}
	return config
}

// jsonFormat encodes as Gin does, without Huma's trailing newline, so
// response bodies stay byte for byte what they were.
var jsonFormat = huma.Format{
	Marshal: func(w io.Writer, v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	},
	Unmarshal: json.Unmarshal,
}

// logCause attaches the cause of an error response to the Gin context, so
// the request log shows what an internal error hides from the client.
func logCause(ctx huma.Context, _ string, v any) (any, error) {
	if e, ok := v.(*codedError); ok && e.cause != nil {
		_ = humagin.Unwrap(ctx).Error(e.cause)
	}
	return v, nil
}

// codedError is every error body: Code is stable for translation, and Message
// is shown for codes the dashboard does not know.
type codedError struct {
	status  int
	cause   error
	Code    string `json:"code"`
	Message string `json:"error"`
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

// Huma builds its own errors, such as for a body that is malformed or misses
// a field, through huma.NewError, which is global.
func init() {
	huma.NewError = newHumaError
}

// newHumaError reports a request Huma rejects as invalid_request. Huma
// answers a body that fails its schema with 422; it stays 400, as before
// Huma, so that 422 keeps meaning a CMDB Provider rejected the request.
func newHumaError(status int, msg string, errs ...error) huma.StatusError {
	if status >= http.StatusInternalServerError {
		return internal(errors.Join(append([]error{errors.New(msg)}, errs...)...))
	}
	if status == http.StatusUnprocessableEntity {
		status = http.StatusBadRequest
	}
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

// errorDetail leaves out the value Huma echoes with a detail, which for a
// malformed body is the whole body, password included.
func errorDetail(err error) string {
	var detail *huma.ErrorDetail
	if !errors.As(err, &detail) || detail.Location == "" {
		return err.Error()
	}
	return fmt.Sprintf("%s (%s)", detail.Message, detail.Location)
}

func internal(cause error) *codedError {
	return &codedError{status: http.StatusInternalServerError, cause: cause, Code: internalError, Message: "internal server error"}
}

// apiError maps an error from a use case to its status and code.
func apiError(err error) *codedError {
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
