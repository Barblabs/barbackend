// Package epss pulls FIRST's daily EPSS score snapshot.
package epss

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"barbackend/internal/feeds"
	"barbackend/internal/feeds/httpx"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

const (
	defaultURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
	dateLayout = "2006-01-02"
)

// Adapter fetches the EPSS score snapshot.
type Adapter struct {
	httpx.Endpoint
}

// New returns an Adapter, defaulting the client and URL when they are empty.
func New(client *http.Client, url string) *Adapter {
	return &Adapter{Endpoint: httpx.NewEndpoint(client, url, defaultURL)}
}

// Pull fetches the snapshot and emits one Vulnerability per score.
func (a *Adapter) Pull(ctx context.Context, emit feeds.Emit) error {
	resp, err := a.Get(ctx, "epss")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("epss: gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	return read(gz, emit)
}

func read(r io.Reader, emit feeds.Emit) error {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	meta, err := reader.Read()
	if err != nil {
		return fmt.Errorf("epss: read metadata: %w", err)
	}
	model, scoreDate, err := metadata(meta)
	if err != nil {
		return fmt.Errorf("epss: %w", err)
	}
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("epss: read header: %w", err)
	}
	if err := checkHeader(header); err != nil {
		return err
	}
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("epss: read row: %w", err)
		}
		if err := emitRow(row, model, scoreDate, emit); err != nil {
			return err
		}
	}
}

func metadata(record []string) (string, string, error) {
	if len(record) == 0 || !strings.HasPrefix(record[0], "#") {
		return "", "", errors.New("want a metadata line starting with #")
	}
	fields := make(map[string]string, len(record))
	for i, value := range record {
		if i == 0 {
			value = strings.TrimPrefix(value, "#")
		}
		key, value, ok := strings.Cut(value, ":")
		if !ok {
			return "", "", fmt.Errorf("bad metadata field %q", value)
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	model := fields["model_version"]
	date := fields["score_date"]
	if model == "" || date == "" {
		return "", "", errors.New("metadata needs model_version and score_date")
	}
	parsed, err := parseDate(date)
	if err != nil {
		return "", "", fmt.Errorf("score date %q: %w", date, err)
	}
	return model, parsed.Format(dateLayout), nil
}

func checkHeader(header []string) error {
	want := []string{"cve", "epss", "percentile"}
	if len(header) != len(want) {
		return fmt.Errorf("epss: unexpected header %v", header)
	}
	for i, field := range header {
		if strings.ToLower(strings.TrimSpace(field)) != want[i] {
			return fmt.Errorf("epss: unexpected header %v", header)
		}
	}
	return nil
}

func emitRow(row []string, model, scoreDate string, emit feeds.Emit) error {
	if len(row) != 3 {
		log.Printf("epss: skipping row %v: want 3 fields", row)
		return nil
	}
	id, ok := stixext.CVEID(row[0])
	if !ok {
		log.Printf("epss: skipping %q: not a CVE ID", row[0])
		return nil
	}
	probability, err := strconv.ParseFloat(strings.TrimSpace(row[1]), 64)
	if err != nil {
		log.Printf("epss: skipping %s: probability %q: %v", id, row[1], err)
		return nil
	}
	percentile, err := strconv.ParseFloat(strings.TrimSpace(row[2]), 64)
	if err != nil {
		log.Printf("epss: skipping %s: percentile %q: %v", id, row[2], err)
		return nil
	}
	v, err := stix2.NewVulnerability(id,
		stix2.OptionCreatedBy(stixext.BarbattackID),
		stix2.OptionExternalReferences([]*stix2.ExternalReference{{Name: "cve", ExternalID: id}}),
		stix2.OptionObjectMarking([]stix2.Identifier{stixext.TLPClear}),
		stix2.OptionExtension(string(stixext.EPSSDefinitionID), stixext.NewEPSS(stixext.EPSS{
			Probability:  probability,
			Percentile:   percentile,
			ScoreDate:    scoreDate,
			ModelVersion: model,
		})),
	)
	if err != nil {
		return fmt.Errorf("epss: %s: %w", id, err)
	}
	v.ID = stixext.VulnerabilityID(id)
	return emit(v)
}

func parseDate(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05-0700", dateLayout} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("want an RFC 3339 or date timestamp")
}
