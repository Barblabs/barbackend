package findings

import "time"

// SetNow makes the Service read the time from now.
func (s *Service) SetNow(now func() time.Time) { s.now = now }

// CloseTimeOf is how long closing Findings that took those durations took.
var CloseTimeOf = closeTime
