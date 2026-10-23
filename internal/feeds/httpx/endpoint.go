package httpx

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type Endpoint struct {
	client *http.Client
	url    string
	header http.Header
}

// NewEndpoint returns an Endpoint, defaulting the client and URL when they are empty.
func NewEndpoint(client *http.Client, url, defaultURL string) Endpoint {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(url) == "" {
		url = defaultURL
	}
	return Endpoint{client: client, url: url}
}

func (e Endpoint) URL() string {
	return e.url
}

// WithURL returns a copy of e that fetches url.
func (e Endpoint) WithURL(url string) Endpoint {
	e.url = url
	return e
}

// SetHeader replaces the request headers with a copy of header.
func (e *Endpoint) SetHeader(header http.Header) {
	e.header = header.Clone()
}

// Get fetches the URL and fails unless the response is 200. The caller closes the body.
func (e Endpoint) Get(ctx context.Context, name string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if e.header != nil {
		req.Header = e.header.Clone()
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s: %s: %s", name, e.url, resp.Status)
	}
	return resp, nil
}
