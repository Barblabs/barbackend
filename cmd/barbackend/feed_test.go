package main

import (
	"testing"
	"time"

	"barbackend/internal/advisories"
	"barbackend/internal/findings"
	"barbackend/internal/scoring"
	"barbackend/internal/techniques"
)

func TestHandledByGivesEachFeedItsUseCase(t *testing.T) {
	feeds := handledBy(findings.New(nil, scoring.Model2, time.Hour), advisories.New(nil), techniques.New(nil), registeredFeeds())

	handled := make(map[string]bool)
	for _, f := range feeds {
		handled[f.Name] = f.Handle != nil
	}
	want := map[string]bool{"nvd": true, "kev": true, "epss": true, "attack": true, "aws": true}
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
