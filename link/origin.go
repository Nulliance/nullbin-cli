// Package link validates Nullbin server origins and parses/formats paste view
// and delete links without exposing secret fragments to servers.
package link

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrInvalidOrigin  = errors.New("link: invalid server origin")
	ErrInsecureScheme = errors.New("link: plain http is only allowed for localhost or loopback addresses")
)

// IsLoopbackHost reports whether host is localhost, 127.0.0.1, or ::1.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// ValidateOrigin validates and canonicalizes a server origin for user inputs
// (such as --server, --api, NULLBIN_SERVER, or config.json).
//
// If no scheme is given (for example "paste.example.com"), "https://" is
// assumed automatically. Explicit "http://" is rejected for all non-loopback
// hosts. A single trailing slash is tolerated and stripped; any non-root path,
// query, fragment, or userinfo is rejected.
func ValidateOrigin(raw string) (string, error) {
	return validateOrigin(raw, true, true)
}

// ValidateCanonicalOrigin strictly validates an origin from an untrusted
// discovery document (such as version.json's api_origin): explicit scheme, no
// trailing slash, no path, no query, no fragment, no userinfo, and HTTPS-only
// (loopback HTTP allowed only when allowLoopbackHTTP is true).
func ValidateCanonicalOrigin(raw string, allowLoopbackHTTP bool) (string, error) {
	origin, err := validateOrigin(raw, false, false)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(origin, "http://") && !allowLoopbackHTTP {
		return "", ErrInsecureScheme
	}
	// Canonical origin from version.json must already match canonical form.
	if origin != raw {
		return "", ErrInvalidOrigin
	}
	return origin, nil
}

func normalizeImplicitHTTPS(raw string) (string, error) {
	if strings.Contains(raw, "://") {
		return raw, nil
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(lower, "http:") || strings.HasPrefix(lower, "https:") {
		return "", ErrInvalidOrigin
	}
	return "https://" + raw, nil
}

func validateOrigin(raw string, allowTrailingSlash, allowImplicitHTTPS bool) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", ErrInvalidOrigin
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "", ErrInvalidOrigin
		}
	}

	input := raw
	if allowImplicitHTTPS {
		var err error
		input, err = normalizeImplicitHTTPS(raw)
		if err != nil {
			return "", err
		}
	}

	u, err := url.Parse(input)
	if err != nil {
		return "", ErrInvalidOrigin
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", ErrInvalidOrigin
	}
	if u.Path != "" && (!allowTrailingSlash || u.Path != "/") {
		return "", ErrInvalidOrigin
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", ErrInvalidOrigin
	}

	switch scheme {
	case "https":
	case "http":
		if !IsLoopbackHost(host) {
			return "", ErrInsecureScheme
		}
	default:
		return "", ErrInvalidOrigin
	}

	port := u.Port()
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", ErrInvalidOrigin
		}
		if (scheme == "https" && p == 443) || (scheme == "http" && p == 80) {
			port = ""
		}
	}

	hostPort := host
	if strings.Contains(host, ":") {
		hostPort = "[" + host + "]"
	}
	if port != "" {
		hostPort = fmt.Sprintf("%s:%s", hostPort, port)
	}
	return scheme + "://" + hostPort, nil
}
