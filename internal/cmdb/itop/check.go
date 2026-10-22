package itop

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/itop/rest"
)

// missingRESTProfile is an iTop user that logged in but lacks the REST
// Services User profile, which iTop requires for the REST API.
const missingRESTProfile cmdb.FailureCode = "missing_rest_profile"

// checkTimeout is short because an admin waits for the check in the
// dashboard, and list_operations reads no data.
const checkTimeout = 15 * time.Second

// iTop reports every login failure with code 1 (UNAUTHORIZED); only the
// message tells a missing profile apart (webservices/rest.php).
const (
	unauthorized       = 1
	restProfileMessage = "REST Services User"
)

func (s settings) CheckCredentials(ctx context.Context) error {
	err := rest.New(s.baseURL, s.auth, rest.Options{Timeout: checkTimeout}).Check(ctx)
	return s.classify(err)
}

// classify turns a failed check into a Failure. A canceled check is not the
// CMDB's fault, so it stays an error. Any other failure left is the transport
// failing, such as DNS, a refused connection, a timeout or a dropped reply.
func (s settings) classify(err error) error {
	var apiErr *rest.APIError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return err
	case errors.As(err, &apiErr) && apiErr.Code == unauthorized && strings.Contains(apiErr.Message, restProfileMessage):
		return s.failure(missingRESTProfile, "the iTop user lacks the REST Services User profile", err)
	case errors.As(err, &apiErr) && apiErr.Code == unauthorized:
		return s.failure(cmdb.InvalidCredentials, "iTop rejected the user or password", err)
	case errors.As(err, &apiErr), errors.Is(err, rest.ErrUnexpectedResponse):
		return s.failure(cmdb.UnexpectedResponse, "the URL does not answer like iTop", err)
	case isTLSError(err):
		return s.failure(cmdb.TLSError, "the TLS handshake with iTop failed", err)
	default:
		return s.failure(cmdb.Unreachable, "iTop is unreachable", err)
	}
}

func (s settings) failure(code cmdb.FailureCode, summary string, cause error) *cmdb.Failure {
	return &cmdb.Failure{Code: code, Message: fmt.Sprintf("%s at %s: %v", summary, s.baseURL.Redacted(), cause)}
}

// plainHTTPAnswer is how net/http reports an https URL served by plain HTTP.
// It drops the underlying tls.RecordHeaderError, so only its text is left.
const plainHTTPAnswer = "server gave HTTP response to HTTPS client"

func isTLSError(err error) bool {
	var (
		verifyErr *tls.CertificateVerificationError
		headerErr tls.RecordHeaderError
		alertErr  tls.AlertError
	)
	return errors.As(err, &verifyErr) || errors.As(err, &headerErr) || errors.As(err, &alertErr) ||
		strings.Contains(err.Error(), plainHTTPAnswer)
}
