package main

import (
	"testing"
	"time"

	"barbackend/internal/findings"
	"barbackend/internal/scoring"
)

func TestHandledByGivesTheFindingsOnlyNVDKEVAndEPSS(t *testing.T) {
	feeds := handledBy(findings.New(nil, scoring.Model1, time.Hour), registeredFeeds())

	handled := make(map[string]bool)
	for _, f := range feeds {
		handled[f.Name] = f.Handle != nil
	}
	want := map[string]bool{"nvd": true, "kev": true, "epss": true, "attack": false, "aws": false}
	for name, h := range want {
		if handled[name] != h {
			t.Errorf("feed %s handled = %t, want %t", name, handled[name], h)
		}
	}
	for _, f := range registeredFeeds() {
		if f.Handle != nil {
			t.Errorf("registered feed %s has a Handle, want feed pull to run without the database", f.Name)
		}
	}
}
