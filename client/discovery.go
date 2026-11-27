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
		origin, err := c.discoverAPIOrigin(ctx)
		if err != nil {
			c.discoverErr = err
			return
		}
		c.apiOrigin = origin
	})
	if c.discoverErr != nil {
		return "", c.discoverErr
	}
	return c.apiOrigin, nil
}

func (c *Client) discoverAPIOrigin(ctx context.Context) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := c.newRequest(reqCtx, http.MethodGet, c.siteOrigin+"/version.json", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("discovering API origin from %s/version.json: %w", c.siteOrigin, err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return c.siteOrigin, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected HTTP %d from %s/version.json", resp.StatusCode, c.siteOrigin)
	}

	obj, err := readBoundedJSONObject(resp, maxJSONBytes)
	if err != nil {
		return "", fmt.Errorf("invalid %s/version.json: %w", c.siteOrigin, err)
	}
	rawOrigin, ok := obj["api_origin"].(string)
	if !ok || rawOrigin == "" {
		return "", errors.New("version.json is missing api_origin")
	}
	if rawOrigin == "same-origin" {
		return c.siteOrigin, nil
	}

	allowLoopbackHTTP := strings.HasPrefix(c.siteOrigin, "http://")
	canonical, err := link.ValidateCanonicalOrigin(rawOrigin, allowLoopbackHTTP)
	if err != nil {
		return "", fmt.Errorf("invalid api_origin in version.json: %w", err)
	}
	return canonical, nil
}

// ServerVersion queries the server's /version.json (if available) and /api/v1/version.
func (c *Client) ServerVersion(ctx context.Context) (*VersionInfo, error) {
	info := &VersionInfo{
		SiteOrigin: c.siteOrigin,
	}

	// Best-effort read of site /version.json (also discovers api_origin if needed).
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if req, err := c.newRequest(reqCtx, http.MethodGet, c.siteOrigin+"/version.json", nil); err == nil {
		if resp, err := c.httpClient.Do(req); err == nil {
			if resp.StatusCode == http.StatusOK {
				if obj, jerr := readBoundedJSONObject(resp, maxJSONBytes); jerr == nil {
					if v, ok := obj["version"].(string); ok {
						info.SiteVersion = v
					}
				}
			}
			drainAndClose(resp.Body)
		}
	}

	apiOrigin, err := c.ResolveAPIOrigin(ctx)
	if err != nil {
		return nil, err
	}
	info.APIOrigin = apiOrigin

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
	if v, ok := obj["version"].(string); ok {
		info.APIVersion = v
	}
	if m, ok := obj["mode"].(string); ok {
		info.APIMode = m
	}
	return info, nil
}
