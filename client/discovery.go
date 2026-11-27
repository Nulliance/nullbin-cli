package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Nulliance/nullbin-cli/link"
)

// isSafeVersionString validates server-reported version strings against
// Nullbin's exact build-version grammar (^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$),
// preventing hostile servers from injecting terminal escapes or spoofed lines.
func isSafeVersionString(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	c0 := s[0]
	if !((c0 >= '0' && c0 <= '9') || (c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z')) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == '+' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func isSafeAPIMode(s string) bool {
	return s == "api" || s == "combined"
}

// ResolveAPIOrigin returns the API origin for this client. When --api was not
// explicitly set, it discovers api_origin from GET <server>/version.json once:
//   - "same-origin" -> <server>
//   - valid canonical HTTPS origin (or loopback HTTP when <server> is loopback HTTP) -> api_origin
//   - 404 (combined/API server without static version.json) -> <server>
//   - any malformed JSON or invalid/downgraded origin -> error (fail closed)
func (c *Client) ResolveAPIOrigin(ctx context.Context) (string, error) {
	if c.apiOrigin != "" {
		return c.apiOrigin, nil
	}
	c.discoverOnce.Do(func() {
		origin, siteVer, err := c.discoverAPIOrigin(ctx)
		if err != nil {
			c.discoverErr = err
			return
		}
		c.apiOrigin = origin
		c.siteVersion = siteVer
	})
	if c.discoverErr != nil {
		return "", c.discoverErr
	}
	return c.apiOrigin, nil
}

func (c *Client) discoverAPIOrigin(ctx context.Context) (origin, siteVersion string, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := c.newRequest(reqCtx, http.MethodGet, c.siteOrigin+"/version.json", nil)
	if err != nil {
		return "", "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("discovering API origin from %s/version.json: %w", c.siteOrigin, err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return c.siteOrigin, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("unexpected HTTP %d from %s/version.json", resp.StatusCode, c.siteOrigin)
	}

	obj, err := readBoundedJSONObject(resp, maxJSONBytes)
	if err != nil {
		return "", "", fmt.Errorf("invalid %s/version.json: %w", c.siteOrigin, err)
	}
	if v, ok := obj["version"].(string); ok && isSafeVersionString(v) {
		siteVersion = v
	}

	rawOrigin, ok := obj["api_origin"].(string)
	if !ok || rawOrigin == "" {
		return "", "", errors.New("version.json is missing api_origin")
	}
	if rawOrigin == "same-origin" {
		return c.siteOrigin, siteVersion, nil
	}

	allowLoopbackHTTP := strings.HasPrefix(c.siteOrigin, "http://")
	canonical, err := link.ValidateCanonicalOrigin(rawOrigin, allowLoopbackHTTP)
	if err != nil {
		return "", "", fmt.Errorf("invalid api_origin in version.json: %w", err)
	}
	return canonical, siteVersion, nil
}

// ServerVersion queries the server's /version.json (if available) and /api/v1/version.
// Server-supplied version/mode fields are strictly allowlisted before returning.
func (c *Client) ServerVersion(ctx context.Context) (*VersionInfo, error) {
	apiOrigin, err := c.ResolveAPIOrigin(ctx)
	if err != nil {
		return nil, err
	}
	info := &VersionInfo{
		SiteOrigin:  c.siteOrigin,
		APIOrigin:   apiOrigin,
		SiteVersion: c.siteVersion,
	}

	// If explicit --api skipped discovery, do one bounded read of /version.json for site version.
	if c.explicitAPI != "" {
		if _, sv, derr := c.discoverAPIOrigin(ctx); derr == nil {
			info.SiteVersion = sv
		}
	}

	apiCtx, apiCancel := context.WithTimeout(ctx, 15*time.Second)
	defer apiCancel()
	req, err := c.newRequest(apiCtx, http.MethodGet, apiOrigin+"/api/v1/version", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching API version: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp)
	}
	obj, err := readBoundedJSONObject(resp, maxJSONBytes)
	if err != nil {
		return nil, err
	}
	if v, ok := obj["version"].(string); ok && isSafeVersionString(v) {
		info.APIVersion = v
	}
	if m, ok := obj["mode"].(string); ok && isSafeAPIMode(m) {
		info.APIMode = m
	}
	return info, nil
}
