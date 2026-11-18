package slack

import (
	"time"

	"barbackend/internal/tenancy"
)

// SetNowForTest controls the clock the sealed install state expires against.
func (s *Service) SetNowForTest(now func() time.Time) { s.now = now }

// SealStateForTest seals an install state without going through StartInstall,
// so a test can age it.
func (s *Service) SealStateForTest(customer tenancy.CustomerID) (string, error) {
	return s.sealState(customer)
}
