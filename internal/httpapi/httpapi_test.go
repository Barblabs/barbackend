package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPing(t *testing.T) {
	t.Parallel()
	rec := newEnv(t).do(httptest.NewRequest(http.MethodGet, "/ping", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := rec.Body.String(), `{"message":"pong"}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}
