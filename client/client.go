package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Nulliance/nullbin-cli/link"
)

const (
	defaultRequestTimeout = 60 * time.Second
	defaultChunkTimeout   = 6 * time.Minute
	defaultStallTimeout   = 150 * time.Second
)

// Client talks to a Nullbin instance with strict transport security, bounded
// responses, no redirects, and no cookies or Referer headers.
type Client struct {
	siteOrigin   string
	explicitAPI  string
	apiOrigin    string
	siteVersion  string
	discoverOnce sync.Once
	discoverErr  error
	httpClient   *http.Client
	stallTimeout time.Duration
	sleepFunc    func(context.Context, time.Duration) error
}

// Option customizes a Client.
type Option func(*Client)

// WithAPIOrigin pins an explicit API origin (Option B) instead of discovering
// api_origin via GET <server>/version.json.
func WithAPIOrigin(apiOrigin string) Option {
	return func(c *Client) {
		c.explicitAPI = apiOrigin
	}
}

// WithHTTPClient replaces the underlying HTTP client (primarily for testing).
// Redirects are always disabled even on custom clients.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			cloned := *hc
			cloned.CheckRedirect = denyRedirects
			cloned.Jar = nil
			c.httpClient = &cloned
		}
	}
}

func denyRedirects(*http.Request, []*http.Request) error {
	return errors.New("HTTP redirects are not allowed")
}

func newHardenedHTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion:    tls.VersionTLS12,
			Renegotiation: tls.RenegotiateNever,
		},
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        4,
		IdleConnTimeout:        60 * time.Second,
		TLSHandshakeTimeout:    15 * time.Second,
		ResponseHeaderTimeout:  defaultRequestTimeout,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
		DisableCompression:     true,
	}
	return &http.Client{
		Transport:     tr,
		CheckRedirect: denyRedirects,
		Jar:           nil,
	}
}

// New constructs a hardened Nullbin Client targeting siteOrigin.
// siteOrigin must be a valid https:// origin (or http:// for localhost/loopback only).
func New(siteOrigin string, opts ...Option) (*Client, error) {
	canonicalSite, err := link.ValidateOrigin(siteOrigin)
	if err != nil {
		return nil, fmt.Errorf("invalid server origin: %w", err)
	}
	c := &Client{
		siteOrigin:   canonicalSite,
		httpClient:   newHardenedHTTPClient(),
		stallTimeout: defaultStallTimeout,
		sleepFunc:    sleepContext,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if c.explicitAPI != "" {
		canonicalAPI, err := link.ValidateOrigin(c.explicitAPI)
		if err != nil {
			return nil, fmt.Errorf("invalid API origin: %w", err)
		}
		if strings.HasPrefix(canonicalSite, "https://") && strings.HasPrefix(canonicalAPI, "http://") {
			return nil, errors.New("refusing plain HTTP API origin for an HTTPS server")
		}
		c.apiOrigin = canonicalAPI
	}
	return c, nil
}

// SiteOrigin returns the canonical site origin used to build share and delete URLs.
func (c *Client) SiteOrigin() string {
	return c.siteOrigin
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) newRequest(ctx context.Context, method, fullURL string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cache-Control", "no-store")
	return req, nil
}

// readBoundedBody reads at most limit bytes from r, failing if the stream exceeds limit.
func readBoundedBody(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("server response exceeded size limit")
	}
	return data, nil
}

func readBoundedJSONObject(resp *http.Response, limit int64) (map[string]any, error) {
	if resp.ContentLength > limit {
		return nil, errors.New("server response exceeded size limit")
	}
	data, err := readBoundedBody(resp.Body, limit)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, errors.New("server sent invalid UTF-8 JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, errors.New("server sent invalid JSON")
	}
	if obj == nil {
		return nil, errors.New("server sent invalid JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("server sent trailing data after JSON")
	}
	return obj, nil
}

func parseRetryAfter(h string) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	secs, err := strconv.Atoi(h)
	if err != nil || secs <= 0 {
		return 0
	}
	if secs > 30 {
		secs = 30
	}
	return time.Duration(secs) * time.Second
}

func parseAPIError(resp *http.Response) *APIError {
	apiErr := &APIError{
		Status:     resp.StatusCode,
		Message:    fmt.Sprintf("HTTP %d", resp.StatusCode),
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
	obj, err := readBoundedJSONObject(resp, maxJSONBytes)
	if err != nil {
		return apiErr
	}
	if rawMsg, ok := obj["error"].(string); ok {
		if _, trusted := trustedAPIErrors[rawMsg]; trusted {
			apiErr.Message = rawMsg
		}
	}
	if rawNext, ok := obj["next_chunk"].(json.Number); ok {
		if n, err := rawNext.Int64(); err == nil && n >= 0 && n <= math.MaxInt32 {
			ni := int(n)
			apiErr.NextChunk = &ni
		}
	}
	if rawMax, ok := obj["max_size"].(json.Number); ok {
		if n, err := rawMax.Int64(); err == nil && n >= 0 {
			apiErr.MaxSize = &n
		}
	}
	return apiErr
}

// drainAndClose discards bounded unread response bytes so HTTP/1.1 keep-alive
// connections can be reused without unbounded reads.
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64*1024))
	_ = body.Close()
}
