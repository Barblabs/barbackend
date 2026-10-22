package ingest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"barbackend/internal/feeds"

	"github.com/TcM1911/stix2"
)

const batchSize = 1000

var ErrUnknownFeed = errors.New("unknown feed")

// Feed is one registered Feed: its name, how often it is polled and how to pull and handle it.
type Feed struct {
	Name     string
	Interval time.Duration
	Pull     feeds.Pull
	Handle   func(ctx context.Context, batch []stix2.STIXObject) error
}

type Result struct {
	Feed  string
	Count int
	Err   error
}

type Service struct {
	feeds []Feed
}

// New registers feeds
func New(feeds ...Feed) (*Service, error) {
	seen := make(map[string]struct{}, len(feeds))
	registered := make([]Feed, len(feeds))
	for i, f := range feeds {
		f.Name = strings.TrimSpace(f.Name)
		if f.Name == "" {
			return nil, errors.New("feed name is blank")
		}
		if f.Interval <= 0 {
			return nil, fmt.Errorf("feed %s: interval must be positive", f.Name)
		}
		if f.Pull == nil {
			return nil, fmt.Errorf("feed %s: pull function is nil", f.Name)
		}
		if _, dup := seen[f.Name]; dup {
			return nil, fmt.Errorf("feed %s is registered twice", f.Name)
		}
		seen[f.Name] = struct{}{}
		registered[i] = f
	}
	return &Service{feeds: registered}, nil
}

// Pull pulls the Feed registered under name and returns its entry count, discarding the entries. An unknown name fails before any pull runs.
func (s *Service) Pull(ctx context.Context, name string) (int, error) {
	name = strings.TrimSpace(name)
	for _, f := range s.feeds {
		if f.Name == name {
			return f.pull(ctx, nil)
		}
	}
	return 0, fmt.Errorf("%w: %s", ErrUnknownFeed, name)
}

// PullAll pulls every registered Feed and returns one Result per Feed
func (s *Service) PullAll(ctx context.Context) []Result {
	results := make([]Result, len(s.feeds))
	for i, f := range s.feeds {
		count, err := f.pull(ctx, nil)
		results[i] = Result{Feed: f.Name, Count: count, Err: err}
	}
	return results
}

// Run pulls every Feed once, immediately, then polls each on its own interval
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, f := range s.feeds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.poll(ctx, f)
		}()
	}
	wg.Wait()
}

func (s *Service) poll(ctx context.Context, f Feed) {
	s.pullAndLog(ctx, f)
	ticker := time.NewTicker(f.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pullAndLog(ctx, f)
			select {
			case <-ticker.C:
			default:
			}
		}
	}
}

func (s *Service) pullAndLog(ctx context.Context, f Feed) {
	if _, err := f.pull(ctx, f.Handle); err != nil {
		log.Printf("feed %s: pull failed: %v", f.Name, err)
	}
}

func (f Feed) pull(ctx context.Context, handle func(context.Context, []stix2.STIXObject) error) (int, error) {
	var count int
	var batch []stix2.STIXObject
	err := f.Pull(ctx, func(obj stix2.STIXObject) error {
		count++
		if handle == nil {
			return nil
		}
		batch = append(batch, obj)
		if len(batch) < batchSize {
			return nil
		}
		if err := handle(ctx, batch); err != nil {
			return err
		}
		batch = nil
		return nil
	})
	if err != nil {
		return count, err
	}
	if len(batch) == 0 {
		return count, nil
	}
	return count, handle(ctx, batch)
}
