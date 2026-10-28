package httpapi

import (
	"fmt"
	"net/http"
	"testing"

	"barbackend/internal/cmdb"
)

// Over HTTP a deactivated Customer is refused when its token is checked, so
// a Sync finding it deactivated mid-request is only reachable from here.
func TestCustomerDeactivatedMidRequestIsForbidden(t *testing.T) {
	e := apiError(fmt.Errorf("cmdb source x: %w", cmdb.ErrCustomerDeactivated))

	if e.status != http.StatusForbidden || e.Code != customerDeactivated {
		t.Errorf("apiError = %d %s, want 403 %s", e.status, e.Code, customerDeactivated)
	}
}
