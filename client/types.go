// Package client implements a zero-knowledge Go client for Nullbin servers.
// All encryption, decryption, padding, and key derivation run locally; the
// server only ever receives ciphertext and derived capability tokens.
package client

import (
	"fmt"
	"io"
	"time"

	"github.com/Nulliance/nullbin-cli/format"
)

const (
	// APIVersion is the Nullbin HTTP API version spoken by this client.
	APIVersion = "v1"

	// UploadChunkSize is the sequential chunk size uploaded to /chunks/{n} (4 MiB).
	UploadChunkSize = 4 * 1024 * 1024
	// MaxBurnReads is the maximum allowed opens per burn paste or recipient link.
	MaxBurnReads = 1000
	// MinRecipients is the minimum number of separate recipient links.
	MinRecipients = 2
	// MaxRecipients is the maximum number of separate recipient links.
	MaxRecipients = 20
	// MaxExpiresInHeader is the upper bound accepted for Nullbin-Expires-In (31 days).
	MaxExpiresInHeader = 31 * 24 * 3600

	maxJSONBytes = 128 * 1024
)

// AllowedExpires maps CLI duration strings to Nullbin server expires_in seconds.
var AllowedExpires = map[string]int{
	"5m":  300,
	"30m": 1800,
	"1h":  3600,
	"3h":  10800,
	"12h": 43200,
	"1d":  86400,
	"3d":  259200,
	"7d":  604800,
	"30d": 2592000,
}

// ParseExpires parses a duration name (5m, 30m, 1h, 3h, 12h, 1d, 3d, 7d, 30d)
// into exact Nullbin expires_in seconds.
func ParseExpires(s string) (int, error) {
	secs, ok := AllowedExpires[s]
	if !ok {
		return 0, fmt.Errorf("invalid expiry %q (allowed: 5m, 30m, 1h, 3h, 12h, 1d, 3d, 7d, 30d)", s)
	}
	return secs, nil
}

// ValidExpiresIn reports whether secs is an allowed server expires_in value.
func ValidExpiresIn(secs int) bool {
	for _, v := range AllowedExpires {
		if v == secs {
			return true
		}
	}
	return false
}

// Trusted allowlist of Nullbin API error messages (mirrors web/src/api.ts).
// Unknown text from a remote server is replaced with "HTTP <status>" so a
// hostile API cannot inject arbitrary text or terminal escapes into errors.
var trustedAPIErrors = map[string]struct{}{
	"a burn-after-reading paste cannot have a discussion":                                           {},
	"burn_token is required only for burn-after-reading pastes and must be 43 base64url characters": {},
	"chunk out of order": {},
	"chunk too large":    {},
	"chunk too small: every chunk but the last must be at least 4 MiB":                        {},
	"comment_token must be 43 base64url characters":                                           {},
	"content type must be application/json":                                                   {},
	"content type must be application/octet-stream":                                           {},
	"could not read request body":                                                             {},
	"empty chunk":                                                                             {},
	"expires_in must be one of 300, 1800, 3600, 10800, 43200, 86400, 259200, 604800":          {},
	"expires_in must be one of 300, 1800, 3600, 10800, 43200, 86400, 259200, 604800, 2592000": {},
	"expires_in, burn_after_reading and total_size are required":                              {},
	"header not allowed":                                                                      {},
	"internal error":                                                                          {},
	"invalid JSON":                                                                            {},
	"invalid chunk index":                                                                     {},
	"invalid request":                                                                         {},
	"max_reads requires burn_after_reading and must be an integer from 1 to 1000":             {},
	"method not allowed":                                                                      {},
	"not found":                                                                               {},
	"origin not allowed":                                                                      {},
	"paste busy, try again":                                                                   {},
	"paste or storage capacity reached":                                                       {},
	"rate limited":                                                                            {},
	"recipients requires burn_after_reading, no burn_token, max_reads or comment_token, and 2 to 20 entries, each a distinct 43-character base64url token with an optional max_reads from 1 to 1000": {},
	"request body too large":                          {},
	"server busy":                                     {},
	"storage capacity reached":                        {},
	"this link was revoked or has used all its opens": {},
	"too many active downloads":                       {},
	"too many active uploads":                         {},
	"too many unfinished uploads":                     {},
	"total_size is too small":                         {},
	"upload busy":                                     {},
	"upload incomplete":                               {},
	"upload too slow":                                 {},
}

// APIError represents an HTTP error returned by the Nullbin API.
type APIError struct {
	Status     int
	Message    string
	NextChunk  *int
	MaxSize    *int64
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	// Give a clear hint when an older nullbin-server rejects a newer feature
	// (such as 30-day expiry, which was added after the 7-day ceiling).
	if e.Message == "expires_in must be one of 300, 1800, 3600, 10800, 43200, 86400, 259200, 604800" {
		return fmt.Sprintf("server error (%d): %s (this server may be running an older version of nullbin-server)", e.Status, e.Message)
	}
	return fmt.Sprintf("server error (%d): %s", e.Status, e.Message)
}

// FileInput describes a local file to attach to a new paste.
type FileInput struct {
	Name string
	MIME string
	Size int64
	Open func() (io.ReadCloser, error)
}

// RecipientSpec defines one separate recipient link (MaxReads == nil means unlimited opens).
type RecipientSpec struct {
	MaxReads *int
}

// CreateOptions configures paste creation.
type CreateOptions struct {
	Text       string
	Files      []FileInput
	ExpiresIn  int
	Burn       bool
	MaxReads   int // used when Burn && len(Recipients) == 0; defaults to 1 if 0
	Recipients []RecipientSpec
	Discussion bool
	Password   []byte // optional; caller should zero after Create returns
}

// CreateResult contains the URLs and metadata returned after uploading and finalizing a paste.
type CreateResult struct {
	ID            string    `json:"id"`
	ViewURL       string    `json:"view_url,omitempty"`
	RecipientURLs []string  `json:"recipient_urls,omitempty"`
	DeleteURL     string    `json:"delete_url"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	TotalSize     int64     `json:"total_size"`
	PasswordUsed  bool      `json:"password_protected"`
	Burn          bool      `json:"burn"`
	Discussion    bool      `json:"discussion"`
	Filename      string    `json:"filename,omitempty"`
}

// ReadOptions configures reading/decrypting a paste.
type ReadOptions struct {
	// Password is an optional pre-supplied password (e.g. from --password-stdin/--password-fd).
	Password []byte
	// PasswordPrompt is called interactively if the paste needs a password and
	// Password is empty or failed. attempt starts at 0.
	PasswordPrompt func(attempt int) ([]byte, error)
	// BeforeBurn is called after fetching the public 22-byte prefix of a burn or
	// recipient paste and BEFORE consuming an open with POST /read. Return a
	// non-nil error to abort without consuming an open.
	BeforeBurn func(prefix format.Prefix) error
}

// ReadResult holds an authenticated paste's metadata and optional attachment stream.
type ReadResult struct {
	ID             string
	Meta           format.PasteMeta
	BlobSize       int64
	ExpiresIn      *int
	ReadsRemaining *int
	HasPassword    bool
	IsBurn         bool
	IsRecipient    bool
	File           io.ReadCloser
	closer         func() error
}

// Close releases the underlying HTTP response and zeros any remaining key state.
func (r *ReadResult) Close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.File != nil {
		err = r.File.Close()
		r.File = nil
	}
	if r.closer != nil {
		if cerr := r.closer(); err == nil {
			err = cerr
		}
		r.closer = nil
	}
	return err
}

// RecipientState mirrors the server's per-link status returned by GET /recipients.
type RecipientState struct {
	Index    int  `json:"index"`
	Opens    int  `json:"opens"`
	MaxOpens *int `json:"max_opens"`
	Revoked  bool `json:"revoked"`
}

// VersionInfo combines optional frontend /version.json and /api/v1/version responses.
type VersionInfo struct {
	SiteOrigin  string `json:"site_origin"`
	APIOrigin   string `json:"api_origin"`
	SiteVersion string `json:"site_version,omitempty"`
	APIVersion  string `json:"api_version,omitempty"`
	APIMode     string `json:"api_mode,omitempty"`
}
