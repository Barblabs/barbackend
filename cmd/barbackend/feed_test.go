package main

import (
	"testing"
	"time"

	"barbackend/internal/advisories"
	"barbackend/internal/findings"
	"barbackend/internal/ingest"
	"barbackend/internal/newsitems"
	"barbackend/internal/scoring"
	"barbackend/internal/techniques"
)

func TestHandledByGivesEachFeedItsUseCase(t *testing.T) {
	feeds := handledBy(findings.New(nil, scoring.Model3, time.Hour), advisories.New(nil), techniques.New(nil), newsitems.New(nil), registeredFeeds())

	handled := make(map[string]bool)
	for _, f := range feeds {
		handled[f.Name] = f.Handle != nil
	}
	want := map[string]bool{"nvd": true, "kev": true, "epss": true, "attack": true, "aws": true, "thehackernews": true, "unaaldia": true}
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

func TestRansomwareLiveIsPolledOnlyWhenEnabled(t *testing.T) {
	t.Setenv("RANSOMWARELIVE_ENABLED", "")
	if registered(registeredFeeds(), ransomwareLive) {
		t.Error("ransomwarelive is registered without RANSOMWARELIVE_ENABLED")
	}
	t.Setenv("RANSOMWARELIVE_ENABLED", "true")
	if !registered(registeredFeeds(), ransomwareLive) {
		t.Error("ransomwarelive is not registered with RANSOMWARELIVE_ENABLED=true")
	}
}

func TestNewsFeedsArePulledHourlyOrEveryTwoHoursInSpanish(t *testing.T) {
	for _, f := range registeredFeeds() {
		want := map[string]time.Duration{"therecord": time.Hour, "welivesecurity": 2 * time.Hour, "unaaldia": 2 * time.Hour}[f.Name]
		if want != 0 && f.Interval != want {
			t.Errorf("feed %s interval = %s, want %s", f.Name, f.Interval, want)
		}
	}
}

func registered(feeds []ingest.Feed, name string) bool {
	for _, f := range feeds {
		if f.Name == name {
			return true
		}
	}
	return false
}
