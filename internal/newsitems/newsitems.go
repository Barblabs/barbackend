// Package newsitems stores the News Items that news Feeds emit, on receipt
// (ADR 0025): unlike a Vulnerability or an Advisory, a News Item is kept
// whether or not it names anything stored, since what makes it relevant is
// known only once it is read. Its Handle has the shape of ingest.Feed.Handle.
package newsitems

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"barbackend/internal/news"
	"barbackend/internal/postgres"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

// Service stores News Items.
type Service struct {
	db *postgres.DB
}

func New(db *postgres.DB) *Service {
	return &Service{db: db}
}

// HandleNews stores every News Item of batch, and the victims they refer to,
// in one transaction. A report without the news/1 extension is not a News
// Item and is left out.
func (s *Service) HandleNews(ctx context.Context, batch []stix2.STIXObject) error {
	items, victims, err := split(batch)
	if err != nil {
		return err
	}
	if len(items) == 0 && len(victims) == 0 {
		return nil
	}
	return s.db.InTx(ctx, func(tx *postgres.Tx) error {
		if err := tx.StoreNews(ctx, items, victims); err != nil {
			return err
		}
		log.Printf("newsitems: stored %d news items and %d victims", len(items), len(victims))
		return nil
	})
}

// split is the News Items and the victims of batch.
func split(batch []stix2.STIXObject) ([]postgres.StoredNewsItem, []postgres.StoredVictim, error) {
	var (
		items   []postgres.StoredNewsItem
		victims []postgres.StoredVictim
	)
	for _, obj := range batch {
		switch o := obj.(type) {
		case *stix2.Identity:
			v, err := victim(o)
			if err != nil {
				return nil, nil, err
			}
			victims = append(victims, v)
		case *stix2.Report:
			item, ok, err := newsItem(o)
			if err != nil {
				return nil, nil, err
			}
			if ok {
				items = append(items, item)
			}
		}
	}
	return items, victims, nil
}

func newsItem(r *stix2.Report) (postgres.StoredNewsItem, bool, error) {
	ext, ok := stixext.NewsOf(r)
	if !ok {
		return postgres.StoredNewsItem{}, false, nil
	}
	object, err := json.Marshal(r)
	if err != nil {
		return postgres.StoredNewsItem{}, false, fmt.Errorf("encode news item %s: %w", r.ID, err)
	}
	var refs []string
	for _, id := range r.Objects {
		if strings.HasPrefix(string(id), string(stix2.TypeIdentity)+"--") && id != stixext.BarbattackID {
			refs = append(refs, string(id))
		}
	}
	return postgres.StoredNewsItem{
		ID:        string(r.ID),
		Feed:      ext.Feed,
		Kind:      ext.Kind,
		Published: timeOf(r.Published),
		CVEs:      news.CVEsOf(r),
		Object:    object,
		Modified:  timeOf(r.Modified),
		Ready:     ext.Kind == stixext.NewsLeakPost,
		Victims:   refs,
	}, true, nil
}

func victim(i *stix2.Identity) (postgres.StoredVictim, error) {
	object, err := json.Marshal(i)
	if err != nil {
		return postgres.StoredVictim{}, fmt.Errorf("encode news victim %s: %w", i.ID, err)
	}
	return postgres.StoredVictim{ID: string(i.ID), Object: object}, nil
}

// timeOf is t, or now when the Feed gave none.
func timeOf(t *stix2.Timestamp) time.Time {
	if t == nil {
		return time.Now().UTC()
	}
	return t.Time
}
