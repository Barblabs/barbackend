// Package rest reads objects from the iTop REST API with core/get, returning
// every matching object or an error.
package rest

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ErrUnexpectedResponse is a reply that is not iTop REST JSON, such as an
// error page or a server that is not iTop.
var ErrUnexpectedResponse = errors.New("unexpected itop response")

// APIError is an error reported by iTop itself, such as an invalid login or
// query. iTop reports them with HTTP 200 and a non-zero code.
type APIError struct {
	Code    int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("itop api error %d: %s", e.Code, e.Message) }

// apiVersion 1.4 is the first with limit and page on core/get (iTop 2.7).
const apiVersion = "1.4"

const (
	defaultPageSize = 500
	defaultTimeout  = time.Minute
)

type Auth struct {
	user, password, token string
}

func BasicAuth(user, password string) Auth { return Auth{user: user, password: password} }

func TokenAuth(token string) Auth { return Auth{token: token} }

type Options struct {
	// PageSize is the most objects one response may hold. Zero means 500.
	PageSize int
	// Timeout bounds each request, response body included. Zero means a minute.
	Timeout time.Duration
}

type Client struct {
	endpoint string
	auth     Auth
	http     *http.Client
	pageSize int
}

func New(baseURL *url.URL, auth Auth, opts Options) *Client {
	if opts.PageSize <= 0 {
		opts.PageSize = defaultPageSize
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	endpoint := baseURL.JoinPath("webservices", "rest.php")
	endpoint.RawQuery = url.Values{"version": {apiVersion}}.Encode()
	return &Client{
		endpoint: endpoint.String(),
		auth:     auth,
		http:     &http.Client{Timeout: opts.Timeout},
		pageSize: opts.PageSize,
	}
}

// Check makes the cheapest authenticated call iTop has, list_operations, so
// a rejected login or a server that is not iTop fails without reading data.
func (c *Client) Check(ctx context.Context) error {
	resp, err := c.post(ctx, []byte(`{"operation":"list_operations"}`))
	if err != nil {
		return err
	}
	if resp.Code != 0 {
		return &APIError{Code: resp.Code, Message: resp.Message}
	}
	if resp.Operations == nil {
		return fmt.Errorf("%w: list_operations returned no operations", ErrUnexpectedResponse)
	}
	return nil
}

// Query selects objects of Class, optionally narrowed by an OQL condition.
type Query struct {
	Class  string
	Where  string
	Fields []string
}

type Object struct {
	// Class is the object's final class, which may be a subclass of the
	// queried one.
	Class  string
	Key    string
	Fields json.RawMessage
}

// Get returns every object matching q, ordered by key.
//
// It reads them in windows of ids rather than with limit and page alone:
// iTop orders results by friendlyname, which is not unique, so offset pages
// can repeat or skip objects that share a name. Each window is one query, and
// a window holding more than a page is halved and read again, so a response
// never exceeds a page however ids are spread. Windows grow while they are
// sparse, because ids are shared by every class of an iTop instance.
func (c *Client) Get(ctx context.Context, q Query) ([]Object, error) {
	var all []Object
	var after, width int64 = 0, int64(c.pageSize)
	for {
		window, err := c.call(ctx, q, fmt.Sprintf("id > %d AND id <= %d", after, after+width), q.Fields, c.pageSize+1)
		if err != nil {
			return nil, err
		}
		if len(window) > c.pageSize {
			width = max(1, width/2)
			continue
		}
		all = append(all, window...)
		after += width
		rest, err := c.call(ctx, q, fmt.Sprintf("id > %d", after), []string{"id"}, 1)
		if err != nil {
			return nil, err
		}
		if len(rest) == 0 {
			return all, nil
		}
		if len(window) < c.pageSize/2 {
			width *= 2
		}
	}
}

type request struct {
	Operation    string `json:"operation"`
	Class        string `json:"class"`
	Key          string `json:"key"`
	OutputFields string `json:"output_fields,omitempty"`
	Limit        int    `json:"limit"`
	Page         int    `json:"page"`
}

type response struct {
	Code    int                       `json:"code"`
	Message string                    `json:"message"`
	Objects map[string]responseObject `json:"objects"`
	// Operations is only answered to list_operations.
	Operations json.RawMessage `json:"operations"`
}

type responseObject struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Class   string          `json:"class"`
	Key     string          `json:"key"`
	Fields  json.RawMessage `json:"fields"`
}

// call runs one core/get of the objects matching both q and idRange, at most
// limit of them, ordered by key.
func (c *Client) call(ctx context.Context, q Query, idRange string, fields []string, limit int) ([]Object, error) {
	oql := fmt.Sprintf("SELECT %s WHERE %s", q.Class, idRange)
	if q.Where != "" {
		oql += " AND (" + q.Where + ")"
	}
	payload, err := json.Marshal(request{
		Operation:    "core/get",
		Class:        q.Class,
		Key:          oql,
		OutputFields: strings.Join(fields, ","),
		Limit:        limit,
		Page:         1,
	})
	if err != nil {
		return nil, err
	}
	resp, err := c.post(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", oql, err)
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("%s: %w", oql, &APIError{Code: resp.Code, Message: resp.Message})
	}
	objects := make([]Object, 0, len(resp.Objects))
	ids := make(map[string]int64, len(resp.Objects))
	for _, o := range resp.Objects {
		if o.Code != 0 {
			return nil, fmt.Errorf("%s: object %s::%s: %w", oql, o.Class, o.Key, &APIError{Code: o.Code, Message: o.Message})
		}
		id, err := strconv.ParseInt(o.Key, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: object %s has a non-numeric key %q", oql, o.Class, o.Key)
		}
		ids[o.Key] = id
		objects = append(objects, Object{Class: o.Class, Key: o.Key, Fields: o.Fields})
	}
	slices.SortFunc(objects, func(a, b Object) int { return cmp.Compare(ids[a.Key], ids[b.Key]) })
	return objects, nil
}

func (c *Client) post(ctx context.Context, payload []byte) (response, error) {
	form := url.Values{"json_data": {string(payload)}}
	if c.auth.token == "" {
		form.Set("auth_user", c.auth.user)
		form.Set("auth_pwd", c.auth.password)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return response{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.auth.token != "" {
		req.Header.Set("Auth-Token", c.auth.token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return response{}, err
	}
	if res.StatusCode != http.StatusOK {
		return response{}, fmt.Errorf("%w: http %d: %.200s", ErrUnexpectedResponse, res.StatusCode, body)
	}
	var r response
	if err := json.Unmarshal(body, &r); err != nil {
		// iTop answers fatal PHP errors with an HTML page and HTTP 200.
		return response{}, fmt.Errorf("%w: decode: %w: %.200s", ErrUnexpectedResponse, err, body)
	}
	return r, nil
}
