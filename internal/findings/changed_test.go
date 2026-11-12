package findings_test

import (
	"context"
	"testing"
)

func TestEveryFeedBatchAndSyncNotifiesAChange(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	notices := 0
	w.findings.OnChanged(func() { notices++ })
	ctx := context.Background()
	steps := map[string]func() error{
		"nvd":        func() error { return w.findings.HandleNVD(ctx, nil) },
		"kev":        func() error { return w.findings.HandleKEV(ctx, nil) },
		"epss":       func() error { return w.findings.HandleEPSS(ctx, nil) },
		"after sync": func() error { return w.findings.AfterSync(ctx, w.source) },
	}

	for name, step := range steps {
		before := notices
		if err := step(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if notices != before+1 {
			t.Errorf("%s notified %d changes, want 1", name, notices-before)
		}
	}
}
