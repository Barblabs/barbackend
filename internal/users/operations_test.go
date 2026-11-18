package users_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"barbackend/internal/users"
)

func TestSyncHealthHasEveryDayEndingToday(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t, &fakeAdmin{})
	users.SetClock(svc, func() time.Time { return time.Date(2026, time.November, 16, 9, 30, 0, 0, time.UTC) })

	days, err := svc.SyncHealth(context.Background(), platformAdmin(t), 3)
	if err != nil {
		t.Fatal(err)
	}

	if len(days) != 3 || !days[0].Start.Equal(time.Date(2026, time.November, 14, 0, 0, 0, 0, time.UTC)) || !days[2].Start.Equal(time.Date(2026, time.November, 16, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("days = %+v, want November 14 to 16", days)
	}
}

func TestSlackDeliveriesListEveryCustomer(t *testing.T) {
	t.Parallel()
	admin := &fakeAdmin{}
	svc, _ := newService(t, admin)
	if _, err := svc.CreateCustomer(context.Background(), platformAdmin(t), "Acme", "ana@example.com"); err != nil {
		t.Fatal(err)
	}

	got, err := svc.SlackDeliveries(context.Background(), platformAdmin(t), 0)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 || got[0].Name != "Acme" || got[0].Sent+got[0].Failed+got[0].Pending != 0 {
		t.Errorf("deliveries = %+v, want Acme with nothing queued", got)
	}
}

func TestOperationsCoverAtMostNinetyDays(t *testing.T) {
	t.Parallel()
	svc, _ := newService(t, &fakeAdmin{})

	if _, err := svc.SyncHealth(context.Background(), platformAdmin(t), users.MaxOperationDays+1); !errors.Is(err, users.ErrInvalidDays) {
		t.Errorf("%d days: err = %v, want ErrInvalidDays", users.MaxOperationDays+1, err)
	}
}
