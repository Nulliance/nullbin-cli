package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	nbcrypto "github.com/Nulliance/nullbin-cli/crypto"
	"github.com/Nulliance/nullbin-cli/format"
	"github.com/Nulliance/nullbin-cli/link"
)

type createPasteRequest struct {
	ExpiresIn        int                   `json:"expires_in"`
	BurnAfterReading bool                  `json:"burn_after_reading"`
	TotalSize        int64                 `json:"total_size"`
	BurnToken        string                `json:"burn_token,omitempty"`
	MaxReads         int                   `json:"max_reads,omitempty"`
	CommentToken     string                `json:"comment_token,omitempty"`
	Recipients       []recipientReqPayload `json:"recipients,omitempty"`
}

type recipientReqPayload struct {
	Token    string `json:"token"`
	MaxReads *int   `json:"max_reads,omitempty"`
}

// Create encrypts a paste locally and uploads it in sequential 4 MiB chunks.
func (c *Client) Create(ctx context.Context, opts CreateOptions) (*CreateResult, error) {
	if len(opts.Files) == 0 && opts.Text == "" {
		return nil, errors.New("add text or attach at least one file")
	}
	if len(opts.Files) > format.MaxFiles {
		return nil, fmt.Errorf("at most %d files can be attached", format.MaxFiles)
	}
	if !ValidExpiresIn(opts.ExpiresIn) {
		return nil, fmt.Errorf("unsupported expires_in value: %d", opts.ExpiresIn)
	}
	hasRecipients := len(opts.Recipients) > 0
	if hasRecipients {
		if len(opts.Recipients) < MinRecipients || len(opts.Recipients) > MaxRecipients {
			return nil, fmt.Errorf("separate recipient links require between %d and %d recipients", MinRecipients, MaxRecipients)
		}
		if opts.Discussion {
			return nil, errors.New("discussions cannot be enabled with separate recipient links")
		}
		for i, r := range opts.Recipients {
			if r.MaxReads != nil && (*r.MaxReads < 1 || *r.MaxReads > MaxBurnReads) {
				return nil, fmt.Errorf("recipient %d max reads must be between 1 and %d", i+1, MaxBurnReads)
			}
		}
	} else {
		if opts.Burn && opts.Discussion {
			return nil, errors.New("burn-after-reading pastes cannot have a discussion")
		}
		if opts.Burn {
			if opts.MaxReads == 0 {
				opts.MaxReads = 1
			}
			if opts.MaxReads < 1 || opts.MaxReads > MaxBurnReads {
				return nil, fmt.Errorf("max reads must be between 1 and %d", MaxBurnReads)
			}
		} else if opts.MaxReads != 0 {
			return nil, errors.New("max reads requires burn-after-reading")
		}
	}

	hasPassword := len(opts.Password) > 0
	if hasPassword {
		if err := nbcrypto.ValidateNewPassword(opts.Password); err != nil {
			return nil, err
		}
	}

	// Prepare single file or deterministic stored ZIP for 2..100 files.
	var (
		fileReader io.ReadCloser
		meta       format.PasteMeta
	)
	meta.Text = opts.Text
	meta.Discussion = opts.Discussion

	switch len(opts.Files) {
	case 0:
		meta.Type = "text"
	case 1:
		f := opts.Files[0]
		if f.Open == nil {
			return nil, errors.New("missing file opener")
		}
		name := f.Name
		if name == "" {
			name = "file"
		}
		name = truncateUTF16(name, format.MaxFilenameLength)
		meta.Type = "file"
		meta.Filename = &name
		if f.MIME != "" {
			m := truncateUTF16(f.MIME, format.MaxMimeLength)
			meta.Mime = &m
		}
		meta.Size = f.Size
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		fileReader = rc
	default:
		zInputs := make([]format.ZipInput, len(opts.Files))
		for i, f := range opts.Files {
			zInputs[i] = format.ZipInput{Name: f.Name, Size: f.Size, Open: f.Open}
		}
		sz, err := format.NewStoredZip(zInputs)
		if err != nil {
			return nil, err
		}
		name := format.ArchiveName(len(opts.Files))
		zipMIME := "application/zip"
		meta.Type = "file"
		meta.Filename = &name
		meta.Mime = &zipMIME
		meta.Size = sz.Size()
		fileReader = sz.Open()
	}
	if fileReader != nil {
		defer fileReader.Close()
	}

	// Resolve API origin before running expensive Argon2id if discovery fails.
	apiOrigin, err := c.ResolveAPIOrigin(ctx)
	if err != nil {
		return nil, err
	}

	// Derive all keys locally.
	fragmentKey, err := nbcrypto.RandomBytes(nbcrypto.KeyBytes)
	if err != nil {
		return nil, err
	}
	defer nbcrypto.Zero(fragmentKey)

	salt := make([]byte, nbcrypto.SaltBytes)
	if hasPassword {
		var serr error
		salt, serr = nbcrypto.RandomBytes(nbcrypto.SaltBytes)
		if serr != nil {
			return nil, serr
		}
	}
	prefix, err := format.BuildPrefix(hasPassword, salt)
	if err != nil {
		return nil, err
	}

	master, err := nbcrypto.DeriveMasterKey(fragmentKey, opts.Password, salt)
	if err != nil {
		return nil, err
	}
	defer nbcrypto.Zero(master)

	streamKey, err := nbcrypto.DeriveStreamKey(master)
	if err != nil {
		return nil, err
	}
	defer nbcrypto.Zero(streamKey)

	var (
		burnToken        string
		commentToken     string
		recipientSecrets [][]byte
		recipientReqs    []recipientReqPayload
	)
	defer func() {
		for _, s := range recipientSecrets {
			nbcrypto.Zero(s)
		}
	}()

	if hasRecipients {
		recipientSecrets = make([][]byte, len(opts.Recipients))
		recipientReqs = make([]recipientReqPayload, len(opts.Recipients))
		for i, r := range opts.Recipients {
			sec, err := nbcrypto.RandomBytes(nbcrypto.RecipientSecretBytes)
			if err != nil {
				return nil, err
			}
			recipientSecrets[i] = sec
			tok, err := nbcrypto.DeriveRecipientToken(master, sec)
			if err != nil {
				return nil, err
			}
			recipientReqs[i] = recipientReqPayload{Token: tok, MaxReads: r.MaxReads}
		}
	} else {
		if opts.Burn {
			burnToken, err = nbcrypto.DeriveBurnToken(master)
			if err != nil {
				return nil, err
			}
		}
		if opts.Discussion {
			commentToken, err = nbcrypto.DeriveCommentToken(master)
			if err != nil {
				return nil, err
			}
		}
	}
	nbcrypto.Zero(master)

	encReader, totalSize, err := format.NewV2EncryptReader(streamKey, prefix, meta, fileReader)
	nbcrypto.Zero(streamKey)
	if err != nil {
		return nil, err
	}
	defer encReader.Close()

	// 1. POST /api/v1/pastes
	createReq := createPasteRequest{
		ExpiresIn:        opts.ExpiresIn,
		BurnAfterReading: opts.Burn || hasRecipients,
		TotalSize:        totalSize,
	}
	if hasRecipients {
		createReq.Recipients = recipientReqs
	} else {
		createReq.CommentToken = commentToken
		if opts.Burn {
			createReq.BurnToken = burnToken
			if opts.MaxReads != 1 {
				createReq.MaxReads = opts.MaxReads
			}
		}
	}

	pasteID, uploadToken, deleteToken, err := c.initUpload(ctx, apiOrigin, createReq)
	if err != nil {
		return nil, err
	}

	// 2. PUT /api/v1/pastes/{id}/chunks/{n} in 4 MiB chunks.
	chunkBuf := make([]byte, UploadChunkSize)
	chunkIndex := 0
	var uploaded int64
	for {
		n, rerr := io.ReadFull(encReader, chunkBuf)
		if n > 0 {
			if err := c.putChunk(ctx, apiOrigin, pasteID, chunkIndex, uploadToken, chunkBuf[:n]); err != nil {
				return nil, err
			}
			uploaded += int64(n)
			chunkIndex++
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	if uploaded != totalSize {
		return nil, fmt.Errorf("encrypted stream size mismatch: uploaded %d, expected %d", uploaded, totalSize)
	}

	// 3. POST /api/v1/pastes/{id}/finalize
	expiresAt, err := c.finalizeUpload(ctx, apiOrigin, pasteID, uploadToken)
	if err != nil {
		return nil, err
	}

	// 4. Construct client-side share & delete URLs.
	deleteURL, err := link.FormatDeleteURL(c.siteOrigin, pasteID, deleteToken, hasRecipients)
	if err != nil {
		return nil, err
	}

	res := &CreateResult{
		ID:           pasteID,
		DeleteURL:    deleteURL,
		ExpiresAt:    expiresAt,
		TotalSize:    totalSize,
		PasswordUsed: hasPassword,
		Burn:         opts.Burn || hasRecipients,
		Discussion:   opts.Discussion,
	}
	if meta.Filename != nil {
		res.Filename = *meta.Filename
	}

	if hasRecipients {
		res.RecipientURLs = make([]string, len(recipientSecrets))
		for i, sec := range recipientSecrets {
			limited := opts.Recipients[i].MaxReads != nil
			u, err := link.FormatViewURL(c.siteOrigin, pasteID, fragmentKey, limited, sec)
			if err != nil {
				return nil, err
			}
			res.RecipientURLs[i] = u
		}
	} else {
		u, err := link.FormatViewURL(c.siteOrigin, pasteID, fragmentKey, opts.Burn, nil)
		if err != nil {
			return nil, err
		}
		res.ViewURL = u
	}

	return res, nil
}

func (c *Client) initUpload(ctx context.Context, apiOrigin string, payload createPasteRequest) (id, uploadToken, deleteToken string, err error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", "", "", err
	}

	reqCtx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()

	req, err := c.newRequest(reqCtx, http.MethodPost, apiOrigin+"/api/v1/pastes", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("creating paste: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return "", "", "", parseAPIError(resp)
	}

	obj, err := readBoundedJSONObject(resp, maxJSONBytes)
	if err != nil {
		return "", "", "", err
	}
	id, _ = obj["id"].(string)
	uploadToken, _ = obj["upload_token"].(string)
	deleteToken, _ = obj["delete_token"].(string)
	if !link.ValidID(id) || !link.ValidToken(uploadToken) || !link.ValidToken(deleteToken) {
		return "", "", "", errors.New("server sent invalid paste creation response")
	}
	return id, uploadToken, deleteToken, nil
}

func (c *Client) putChunk(ctx context.Context, apiOrigin, id string, n int, uploadToken string, data []byte) error {
	endpoint := fmt.Sprintf("%s/api/v1/pastes/%s/chunks/%d", apiOrigin, id, n)
	for attempt := 0; ; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, defaultChunkTimeout)
		req, err := c.newRequest(reqCtx, http.MethodPut, endpoint, bytes.NewReader(data))
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Nullbin-Upload-Token", uploadToken)
		req.ContentLength = int64(len(data))

		resp, doErr := c.httpClient.Do(req)
		if doErr != nil {
			cancel()
			if attempt >= 3 || ctx.Err() != nil {
				return fmt.Errorf("uploading chunk %d: %w", n, doErr)
			}
			if err := c.sleepFunc(ctx, time.Second<<attempt); err != nil {
				return err
			}
			continue
		}

		status := resp.StatusCode
		if status == http.StatusNoContent {
			drainAndClose(resp.Body)
			cancel()
			return nil
		}

		apiErr := parseAPIError(resp)
		drainAndClose(resp.Body)
		cancel()

		busy := false
		if status == http.StatusConflict {
			if attempt > 0 && apiErr.NextChunk != nil && *apiErr.NextChunk == n+1 {
				return nil
			}
			if apiErr.NextChunk != nil || attempt >= 3 {
				return apiErr
			}
			busy = true
		}

		retryable := busy || status == http.StatusTooManyRequests || (status >= 500 && status != http.StatusInsufficientStorage)
		if !retryable || attempt >= 3 {
			return apiErr
		}

		wait := apiErr.RetryAfter
		if wait == 0 {
			wait = time.Second << attempt
		}
		if err := c.sleepFunc(ctx, wait); err != nil {
			return err
		}
	}
}

func (c *Client) finalizeUpload(ctx context.Context, apiOrigin, id, uploadToken string) (time.Time, error) {
	endpoint := fmt.Sprintf("%s/api/v1/pastes/%s/finalize", apiOrigin, id)
	for attempt := 0; ; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
		req, err := c.newRequest(reqCtx, http.MethodPost, endpoint, nil)
		if err != nil {
			cancel()
			return time.Time{}, err
		}
		req.Header.Set("Nullbin-Upload-Token", uploadToken)

		resp, doErr := c.httpClient.Do(req)
		if doErr != nil {
			cancel()
			if attempt >= 4 || ctx.Err() != nil {
				return time.Time{}, fmt.Errorf("finalizing paste: %w", doErr)
			}
			if err := c.sleepFunc(ctx, time.Second<<attempt); err != nil {
				return time.Time{}, err
			}
			continue
		}

		if resp.StatusCode == http.StatusOK {
			obj, jerr := readBoundedJSONObject(resp, maxJSONBytes)
			drainAndClose(resp.Body)
			cancel()
			if jerr != nil {
				return time.Time{}, jerr
			}
			if raw, ok := obj["expires_at"].(string); ok {
				if ts, perr := time.Parse(time.RFC3339, raw); perr == nil {
					return ts, nil
				}
			}
			return time.Time{}, nil
		}

		apiErr := parseAPIError(resp)
		drainAndClose(resp.Body)
		cancel()

		retryable := resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable
		if !retryable || attempt >= 4 {
			return time.Time{}, apiErr
		}
		wait := apiErr.RetryAfter
		if wait == 0 {
			wait = time.Second << attempt
		}
		if err := c.sleepFunc(ctx, wait); err != nil {
			return time.Time{}, err
		}
	}
}

func truncateUTF16(s string, maxUnits int) string {
	units := 0
	for i, r := range s {
		n := 1
		if r > 0xFFFF {
			n = 2
		}
		if units+n > maxUnits {
			return s[:i]
		}
		units += n
	}
	return s
}
