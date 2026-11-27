package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	nbcrypto "github.com/Nulliance/nullbin-cli/crypto"
	"github.com/Nulliance/nullbin-cli/format"
	"github.com/Nulliance/nullbin-cli/link"
)

// Read downloads, authenticates, and decrypts a paste from a parsed ViewLink.
//
// For text pastes, Read verifies the complete ciphertext stream before returning.
// For file pastes, callers MUST stream ReadResult.File until io.EOF before
// committing any decrypted bytes to disk, and always call ReadResult.Close().
func (c *Client) Read(ctx context.Context, vl *link.ViewLink, opts ReadOptions) (*ReadResult, error) {
	if vl == nil || !link.ValidID(vl.ID) || len(vl.Key) != nbcrypto.KeyBytes {
		return nil, link.ErrInvalidURL
	}
	apiOrigin, err := c.ResolveAPIOrigin(ctx)
	if err != nil {
		return nil, err
	}

	isRecipient := vl.RecipientSecret != nil
	needsBurnAuth := vl.Burn || isRecipient

	var (
		resp           *http.Response
		readsRemaining *int
		expiresIn      *int
		resolvedPW     []byte
		hasPassword    bool
		isBurn         = vl.Burn
	)
	defer func() {
		nbcrypto.Zero(resolvedPW)
	}()

	if needsBurnAuth {
		prefix, err := c.fetchBurnPrefix(ctx, apiOrigin, vl.ID)
		if err != nil {
			return nil, err
		}

		if opts.BeforeBurn != nil {
			if err := opts.BeforeBurn(prefix); err != nil {
				return nil, err
			}
		}

		for attempt := 0; ; attempt++ {
			var pw []byte
			if prefix.Password {
				if attempt == 0 && len(opts.Password) > 0 {
					pw = append([]byte(nil), opts.Password...)
				} else if opts.PasswordPrompt != nil {
					pw, err = opts.PasswordPrompt(attempt)
					if err != nil {
						return nil, err
					}
					if pw == nil {
						return nil, &format.PasteError{Code: format.CodeCancelled, Message: "cancelled"}
					}
				} else {
					if attempt == 0 {
						return nil, &format.PasteError{Code: format.CodeWrongPassword, Message: "paste requires a password"}
					}
					return nil, &format.PasteError{Code: format.CodeWrongPassword, Message: "incorrect password"}
				}
			}

			master, err := nbcrypto.DeriveMasterKey(vl.Key, pw, prefix.Salt[:])
			if err != nil {
				nbcrypto.Zero(pw)
				return nil, err
			}
			var token string
			if isRecipient {
				token, err = nbcrypto.DeriveRecipientToken(master, vl.RecipientSecret)
			} else {
				token, err = nbcrypto.DeriveBurnToken(master)
			}
			nbcrypto.Zero(master)
			if err != nil {
				nbcrypto.Zero(pw)
				return nil, err
			}

			r, rr, ei, ferr := c.fetchCiphertext(ctx, apiOrigin, vl.ID, token, vl.Burn, isRecipient)
			if ferr == nil {
				resp = r
				readsRemaining = rr
				expiresIn = ei
				resolvedPW = pw
				break
			}
			nbcrypto.Zero(pw)

			var apiErr *APIError
			if !errors.As(ferr, &apiErr) || apiErr.Status != http.StatusNotFound || !prefix.Password {
				return nil, ferr
			}
			// Re-check /prefix: if it still exists (200), the password was wrong.
			// If /prefix now 404s, the paste expired or was burned.
			if _, perr := c.fetchBurnPrefix(ctx, apiOrigin, vl.ID); perr != nil {
				return nil, ferr
			}
			if opts.PasswordPrompt == nil {
				return nil, &format.PasteError{Code: format.CodeWrongPassword, Message: "incorrect password"}
			}
		}
	} else {
		r, rr, ei, ferr := c.fetchCiphertext(ctx, apiOrigin, vl.ID, "", false, false)
		if ferr != nil {
			return nil, ferr
		}
		resp = r
		readsRemaining = rr
		expiresIn = ei
	}

	// For a recipient link, the server's presence/absence of Nullbin-Reads-Remaining
	// determines whether the link has an open limit.
	if isRecipient {
		isBurn = readsRemaining != nil
	}

	pwCallback := func(attempt int, _ [format.SaltBytes]byte) ([]byte, error) {
		if attempt == 0 && len(resolvedPW) > 0 {
			cp := append([]byte(nil), resolvedPW...)
			return cp, nil
		}
		if attempt == 0 && len(opts.Password) > 0 {
			cp := append([]byte(nil), opts.Password...)
			return cp, nil
		}
		if opts.PasswordPrompt == nil {
			if attempt == 0 {
				return nil, &format.PasteError{Code: format.CodeWrongPassword, Message: "paste requires a password"}
			}
			return nil, &format.PasteError{Code: format.CodeWrongPassword, Message: "incorrect password"}
		}
		return opts.PasswordPrompt(attempt)
	}

	stallSrc := newStallReader(ctx, resp.Body, c.stallTimeout)
	opened, err := format.OpenBlob(stallSrc, vl.Key, pwCallback)
	if err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	hasPassword = opened.Prefix.Password

	res := &ReadResult{
		ID:             vl.ID,
		Meta:           opened.Meta,
		BlobSize:       opened.BlobSize,
		ExpiresIn:      expiresIn,
		ReadsRemaining: readsRemaining,
		HasPassword:    hasPassword,
		IsBurn:         isBurn,
		IsRecipient:    isRecipient,
	}

	if opened.File == nil {
		// Entire text paste stream and EOF have been authenticated.
		_ = opened.Close()
		_ = resp.Body.Close()
		return res, nil
	}

	res.File = &closingFileReader{
		file: opened.File,
		onClose: func() error {
			err1 := opened.Close()
			err2 := resp.Body.Close()
			if err1 != nil {
				return err1
			}
			return err2
		},
	}
	res.closer = func() error {
		err1 := opened.Close()
		err2 := resp.Body.Close()
		if err1 != nil {
			return err1
		}
		return err2
	}
	return res, nil
}

func (c *Client) fetchBurnPrefix(ctx context.Context, apiOrigin, id string) (format.Prefix, error) {
	reqCtx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()

	req, err := c.newRequest(reqCtx, http.MethodGet, fmt.Sprintf("%s/api/v1/pastes/%s/prefix", apiOrigin, id), nil)
	if err != nil {
		return format.Prefix{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return format.Prefix{}, fmt.Errorf("fetching paste prefix: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return format.Prefix{}, parseAPIError(resp)
	}
	buf, err := readBoundedBody(resp.Body, format.PrefixBytes)
	if err != nil || len(buf) != format.PrefixBytes {
		return format.Prefix{}, errors.New("server sent invalid paste prefix")
	}
	return format.ParsePrefix(buf)
}

func (c *Client) fetchCiphertext(ctx context.Context, apiOrigin, id, burnToken string, limited, recipientLink bool) (*http.Response, *int, *int, error) {
	method := http.MethodGet
	endpoint := fmt.Sprintf("%s/api/v1/pastes/%s", apiOrigin, id)
	if burnToken != "" {
		method = http.MethodPost
		endpoint += "/read"
	}

	req, err := c.newRequest(ctx, method, endpoint, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	if burnToken != "" {
		req.Header.Set("Nullbin-Burn-Token", burnToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("downloading paste: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		apiErr := parseAPIError(resp)
		drainAndClose(resp.Body)
		return nil, nil, nil, apiErr
	}

	var readsRemaining *int
	if burnToken != "" && (limited || recipientLink) {
		raw := resp.Header.Get("Nullbin-Reads-Remaining")
		if raw == "" {
			if !recipientLink {
				zero := 0
				readsRemaining = &zero
			}
		} else {
			v, perr := parseNonNegInt(raw)
			if perr != nil || v < 0 || v >= MaxBurnReads {
				_ = resp.Body.Close()
				return nil, nil, nil, errors.New("server sent invalid Nullbin-Reads-Remaining header")
			}
			readsRemaining = &v
		}
	}

	var expiresIn *int
	if raw := resp.Header.Get("Nullbin-Expires-In"); raw != "" {
		if len(raw) <= 8 {
			if v, perr := parseNonNegInt(raw); perr == nil && v >= 0 && v <= MaxExpiresInHeader {
				expiresIn = &v
			}
		}
	}

	return resp, readsRemaining, expiresIn, nil
}

func parseNonNegInt(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty integer")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("non-digit")
		}
	}
	return strconv.Atoi(s)
}

type closingFileReader struct {
	file    io.ReadCloser
	onClose func() error
	closed  bool
}

func (r *closingFileReader) Read(p []byte) (int, error) {
	return r.file.Read(p)
}

func (r *closingFileReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.onClose()
}

// stallReader enforces a per-read stall timeout so an unresponsive server
// cannot hang a download indefinitely.
type stallReader struct {
	ctx     context.Context
	body    io.ReadCloser
	timeout time.Duration
}

func newStallReader(ctx context.Context, body io.ReadCloser, timeout time.Duration) *stallReader {
	if timeout <= 0 {
		timeout = defaultStallTimeout
	}
	return &stallReader{ctx: ctx, body: body, timeout: timeout}
}

func (s *stallReader) Read(p []byte) (int, error) {
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := s.body.Read(p)
		ch <- res{n, err}
	}()

	timer := time.NewTimer(s.timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-timer.C:
		_ = s.body.Close()
		return 0, errors.New("download stalled: no data received before timeout")
	case <-s.ctx.Done():
		_ = s.body.Close()
		return 0, s.ctx.Err()
	}
}
