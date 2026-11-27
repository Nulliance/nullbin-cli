// Package link validates Nullbin server origins and parses/formats paste view
// and delete links without exposing secret fragments to servers.
package link

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrInvalidOrigin  = errors.New("link: invalid server origin")
	ErrInsecureScheme = errors.New("link: plain http is only allowed for localhost or loopback addresses")
)

// IsLoopbackHost reports whether host is localhost or a loopback IP address
// (127.0.0.0/8 or ::1) without an IPv6 zone identifier.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(h)
	return err == nil && addr.Zone() == "" && addr.IsLoopback()
}

// ValidateOrigin validates and canonicalizes a server origin for user inputs
// (such as --server, --api, NULLBIN_SERVER, or config.json).
//
// If no scheme is given (for example "paste.example.com"), "https://" is
// assumed automatically. Explicit "http://" is rejected for all non-loopback
// hosts. A single trailing slash is tolerated and stripped; any non-root path,
// query, fragment, userinfo, percent-encoding, backslash, non-ASCII hostname,
// or invalid port is rejected.
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

// rejectedBareSchemes are common URI schemes that must never be reinterpreted
// as a hostname when no "://" separator is present (e.g. "http:example.com",
// "ftp:21", "javascript:alert(1)").
var rejectedBareSchemes = []string{
	"http:", "https:", "ftp:", "ftps:", "file:", "data:",
	"javascript:", "mailto:", "ws:", "wss:", "ssh:", "tel:", "urn:",
}

func normalizeImplicitHTTPS(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", ErrInvalidOrigin
	}
	if strings.Contains(raw, "://") {
		return raw, nil
	}
	if strings.HasPrefix(raw, "//") {
		return "", ErrInvalidOrigin
	}
	lower := strings.ToLower(raw)
	for _, prefix := range rejectedBareSchemes {
		if strings.HasPrefix(lower, prefix) {
			return "", ErrInvalidOrigin
		}
	}
	return "https://" + raw, nil
}

func hasForbiddenRawChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || c == '*' || c == '%' || c == '\\' {
			return true
		}
	}
	return false
}

// isValidASCIIHost validates that host is either a plain IP literal (no zone)
// or a strict RFC 1123 ASCII hostname (letters, digits, hyphens, dots only).
// Rejecting non-ASCII hostnames prevents Unicode/IDN homograph spoofing.
func isValidASCIIHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func validateOrigin(raw string, allowTrailingSlash, allowImplicitHTTPS bool) (string, error) {
	if raw == "" || hasForbiddenRawChars(raw) {
		return "", ErrInvalidOrigin
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
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return "", ErrInvalidOrigin
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", ErrInvalidOrigin
	}
	if u.Path != "" && (!allowTrailingSlash || u.Path != "/") {
		return "", ErrInvalidOrigin
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if !isValidASCIIHost(host) {
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
		if err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
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
