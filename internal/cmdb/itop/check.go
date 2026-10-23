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

const checkTimeout = 15 * time.Second

// iTop reports every login failure with code 1 (UNAUTHORIZED); only the
// message tells a missing profile apart (webservices/rest.php).
const (
	unauthorized       = 1
	restProfileMessage = "REST Services User"
)

func (s settings) CheckCredentials(ctx context.Context) error {
	return s.classify(rest.New(s.baseURL, s.auth, rest.Options{Timeout: checkTimeout}).Check(ctx))
}

func (s settings) classify(err error) error {
	var apiErr *rest.APIError
	switch {
	case err == nil, errors.Is(err, context.Canceled):
		return err
	case errors.As(err, &apiErr) && apiErr.Code == unauthorized && strings.Contains(apiErr.Message, restProfileMessage):
		return s.failure(missingRESTProfile, "the iTop user lacks the REST Services User profile", err)
	case errors.As(err, &apiErr) && apiErr.Code == unauthorized:
		return s.failure(cmdb.InvalidCredentials, "iTop rejected the user or password", err)
	case errors.As(err, &apiErr), errors.Is(err, rest.ErrUnexpectedResponse):
		return s.failure(cmdb.UnexpectedResponse, "iTop did not answer as expected", err)
	case errors.Is(err, rest.ErrTransport) && isTLSError(err):
		return s.failure(cmdb.TLSError, "the TLS handshake with iTop failed", err)
	case errors.Is(err, rest.ErrTransport):
		return s.failure(cmdb.Unreachable, "iTop is unreachable", err)
	default:
		return err
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
