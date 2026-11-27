package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nulliance/nullbin-cli/format"
	"github.com/Nulliance/nullbin-cli/link"
)

type mockPaste struct {
	id         string
	uploadTok  string
	deleteTok  string
	burn       bool
	burnHash   [32]byte
	maxReads   int
	readsUsed  int
	totalSize  int64
	chunks     bytes.Buffer
	nextChunk  int
	finalized  bool
	recipients []mockRecipient
}

type mockRecipient struct {
	hash     [32]byte
	opens    int
	maxOpens *int
	revoked  bool
}

type mockServer struct {
	mu                 sync.Mutex
	pastes             map[string]*mockPaste
	apiOrigin          string
	failChunk0Once     bool
	chunk0Failed       bool
	simulate409RetryOK bool
	chunk0Retried      bool
}

func newMockServer() *mockServer {
	return &mockServer{
		pastes:    make(map[string]*mockPaste),
		apiOrigin: "same-origin",
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (m *mockServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /version.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":    "v0.9.0-test",
			"api_origin": m.apiOrigin,
		})
	})
	mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": "v0.9.0-test",
			"mode":    "api",
		})
	})
	mux.HandleFunc("POST /api/v1/pastes", func(w http.ResponseWriter, r *http.Request) {
		var req createPasteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		id := randomHex(16)
		p := &mockPaste{
			id:        id,
			uploadTok: randomToken(),
			deleteTok: randomToken(),
			burn:      req.BurnAfterReading,
			maxReads:  max(1, req.MaxReads),
			totalSize: req.TotalSize,
		}
		if req.BurnToken != "" {
			p.burnHash = sha256.Sum256([]byte(req.BurnToken))
		}
		for _, rcpt := range req.Recipients {
			p.recipients = append(p.recipients, mockRecipient{
				hash:     sha256.Sum256([]byte(rcpt.Token)),
				maxOpens: rcpt.MaxReads,
			})
		}
		m.mu.Lock()
		m.pastes[id] = p
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":           id,
			"upload_token": p.uploadTok,
			"delete_token": p.deleteTok,
		})
	})
	mux.HandleFunc("PUT /api/v1/pastes/{id}/chunks/{n}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		n, _ := strconv.Atoi(r.PathValue("n"))
		data, _ := io.ReadAll(r.Body)

		m.mu.Lock()
		defer m.mu.Unlock()
		p := m.pastes[id]
		if p == nil || r.Header.Get("Nullbin-Upload-Token") != p.uploadTok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if n == 0 && m.failChunk0Once && !m.chunk0Failed {
			m.chunk0Failed = true
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"server busy"}`))
			return
		}
		if n == 0 && m.simulate409RetryOK {
			if !m.chunk0Retried {
				m.chunk0Retried = true
				p.chunks.Write(data)
				p.nextChunk = 1
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal error"}`))
				return
			}
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "chunk out of order", "next_chunk": p.nextChunk})
			return
		}
		if n != p.nextChunk {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "chunk out of order", "next_chunk": p.nextChunk})
			return
		}
		p.chunks.Write(data)
		p.nextChunk++
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/pastes/{id}/finalize", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		m.mu.Lock()
		defer m.mu.Unlock()
		p := m.pastes[id]
		if p == nil || r.Header.Get("Nullbin-Upload-Token") != p.uploadTok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		p.finalized = true
		_ = json.NewEncoder(w).Encode(map[string]string{
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc("GET /api/v1/pastes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		m.mu.Lock()
		defer m.mu.Unlock()
		p := m.pastes[id]
		if p == nil || !p.finalized || p.burn {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Nullbin-Expires-In", "3599")
		_, _ = w.Write(p.chunks.Bytes())
	})
	mux.HandleFunc("GET /api/v1/pastes/{id}/prefix", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		m.mu.Lock()
		defer m.mu.Unlock()
		p := m.pastes[id]
		if p == nil || !p.finalized || !p.burn {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(p.chunks.Bytes()[:format.PrefixBytes])
	})
	mux.HandleFunc("POST /api/v1/pastes/{id}/read", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		tok := r.Header.Get("Nullbin-Burn-Token")
		h := sha256.Sum256([]byte(tok))
		m.mu.Lock()
		defer m.mu.Unlock()
		p := m.pastes[id]
		if p == nil || !p.finalized || !p.burn {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if len(p.recipients) > 0 {
			for i := range p.recipients {
				rcpt := &p.recipients[i]
				if rcpt.hash == h {
					if rcpt.revoked || (rcpt.maxOpens != nil && rcpt.opens >= *rcpt.maxOpens) {
						w.WriteHeader(http.StatusGone)
						_, _ = w.Write([]byte(`{"error":"this link was revoked or has used all its opens"}`))
						return
					}
					rcpt.opens++
					if rcpt.maxOpens != nil {
						w.Header().Set("Nullbin-Reads-Remaining", strconv.Itoa(*rcpt.maxOpens-rcpt.opens))
					}
					w.Header().Set("Nullbin-Expires-In", "3500")
					_, _ = w.Write(p.chunks.Bytes())
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if p.burnHash != h {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if p.readsUsed >= p.maxReads {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		p.readsUsed++
		rem := p.maxReads - p.readsUsed
		w.Header().Set("Nullbin-Reads-Remaining", strconv.Itoa(rem))
		w.Header().Set("Nullbin-Expires-In", "3500")
		data := append([]byte(nil), p.chunks.Bytes()...)
		if rem == 0 {
			delete(m.pastes, id)
		}
		_, _ = w.Write(data)
	})
	mux.HandleFunc("DELETE /api/v1/pastes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		m.mu.Lock()
		defer m.mu.Unlock()
		p := m.pastes[id]
		if p == nil || r.Header.Get("Nullbin-Delete-Token") != p.deleteTok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(m.pastes, id)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/pastes/{id}/recipients", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		m.mu.Lock()
		defer m.mu.Unlock()
		p := m.pastes[id]
		if p == nil || r.Header.Get("Nullbin-Delete-Token") != p.deleteTok || len(p.recipients) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		list := make([]map[string]any, len(p.recipients))
		for i, rcpt := range p.recipients {
			list[i] = map[string]any{
				"opens":     rcpt.opens,
				"max_opens": rcpt.maxOpens,
				"revoked":   rcpt.revoked,
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"recipients": list})
	})
	mux.HandleFunc("POST /api/v1/pastes/{id}/recipients/{n}/revoke", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		n, _ := strconv.Atoi(r.PathValue("n"))
		m.mu.Lock()
		defer m.mu.Unlock()
		p := m.pastes[id]
		if p == nil || r.Header.Get("Nullbin-Delete-Token") != p.deleteTok || n < 0 || n >= len(p.recipients) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		p.recipients[n].revoked = true
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

type handlerTransport struct {
	h http.Handler
}

func (ht handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	ht.h.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func TestClientEndToEndLifecycle(t *testing.T) {
	ms := newMockServer()
	ms.simulate409RetryOK = true
	baseURL := "https://paste.example.test"

	c, err := New(baseURL, WithHTTPClient(&http.Client{Transport: handlerTransport{h: ms.handler()}}))
	if err != nil {
		t.Fatal(err)
	}
	c.sleepFunc = func(context.Context, time.Duration) error { return nil }

	ctx := context.Background()
	// 1. Create + Read + Delete normal paste (tests 409 next_chunk idempotency too).
	created, err := c.Create(ctx, CreateOptions{
		Text:      "secret text payload",
		ExpiresIn: 3600,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	vl, err := link.ParseViewURL(created.ViewURL)
	if err != nil {
		t.Fatalf("ParseViewURL: %v", err)
	}
	defer vl.Close()

	readRes, err := c.Read(ctx, vl, ReadOptions{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	defer readRes.Close()
	if readRes.Meta.Text != "secret text payload" {
		t.Fatalf("got text %q, want %q", readRes.Meta.Text, "secret text payload")
	}

	dl, err := link.ParseDeleteURL(created.DeleteURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, dl); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// 2. Burn paste with password + BeforeBurn gate.
	ms.simulate409RetryOK = false
	pw := []byte("correct horse battery")
	burnCreated, err := c.Create(ctx, CreateOptions{
		Text:      "burn secret",
		ExpiresIn: 300,
		Burn:      true,
		MaxReads:  1,
		Password:  pw,
	})
	if err != nil {
		t.Fatalf("Create burn: %v", err)
	}
	bvl, err := link.ParseViewURL(burnCreated.ViewURL)
	if err != nil {
		t.Fatal(err)
	}
	defer bvl.Close()

	// Wrong password must NOT consume the burn paste!
	_, err = c.Read(ctx, bvl, ReadOptions{Password: []byte("wrong password")})
	var pe *format.PasteError
	if !errors.As(err, &pe) || pe.Code != format.CodeWrongPassword {
		t.Fatalf("wrong password err = %v, want CodeWrongPassword", err)
	}

	// Correct password now succeeds and burns it.
	beforeCalled := false
	burnRead, err := c.Read(ctx, bvl, ReadOptions{
		Password: pw,
		BeforeBurn: func(p format.Prefix) error {
			beforeCalled = true
			if !p.Password {
				t.Fatal("expected prefix.Password = true")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Read burn: %v", err)
	}
	defer burnRead.Close()
	if !beforeCalled || burnRead.Meta.Text != "burn secret" || burnRead.ReadsRemaining == nil || *burnRead.ReadsRemaining != 0 {
		t.Fatalf("unexpected burn read: %+v", burnRead)
	}

	// 3. Separate recipient links: list, read, revoke.
	one := 1
	rcptCreated, err := c.Create(ctx, CreateOptions{
		Text:      "for two people",
		ExpiresIn: 3600,
		Recipients: []RecipientSpec{
			{MaxReads: &one},
			{MaxReads: nil},
		},
	})
	if err != nil {
		t.Fatalf("Create recipients: %v", err)
	}
	if len(rcptCreated.RecipientURLs) != 2 {
		t.Fatalf("got %d recipient URLs, want 2", len(rcptCreated.RecipientURLs))
	}
	rdl, err := link.ParseDeleteURL(rcptCreated.DeleteURL)
	if err != nil {
		t.Fatal(err)
	}
	list, err := c.ListRecipients(ctx, rdl)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListRecipients: %v, %+v", err, list)
	}
	if err := c.RevokeRecipient(ctx, rdl, 1); err != nil {
		t.Fatalf("RevokeRecipient: %v", err)
	}
	rvl1, _ := link.ParseViewURL(rcptCreated.RecipientURLs[1])
	defer rvl1.Close()
	_, err = c.Read(ctx, rvl1, ReadOptions{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusGone {
		t.Fatalf("revoked recipient read err = %v, want 410", err)
	}
}

func TestClientRejectsRedirectsAndUntrustedErrors(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version.json":
			http.Redirect(w, r, "https://evil.example/", http.StatusFound)
		case "/api/v1/version":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"\u001b]52;c;evil\u0007"}`))
		}
	})
	baseURL := "https://paste.example.test"
	hc := &http.Client{Transport: handlerTransport{h: h}}

	c, err := New(baseURL, WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveAPIOrigin(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}

	c2, err := New(baseURL, WithAPIOrigin(baseURL), WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c2.ServerVersion(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %v", err)
	}
	if strings.Contains(apiErr.Message, "\x1b") || apiErr.Message != "HTTP 400" {
		t.Fatalf("untrusted error text leaked: %q", apiErr.Message)
	}
}

func TestClientDropsMaliciousVersionStringsAndRejectsTrailingJSON(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version.json":
			_, _ = w.Write([]byte(`{"version":"\u001b]52;c;evil\u0007","api_origin":"same-origin"}`))
		case "/api/v1/version":
			_, _ = w.Write([]byte(`{"version":"v1.2.3\nINJECTED","mode":"evil-mode"}`))
		}
	})
	c, err := New("paste.example.test", WithHTTPClient(&http.Client{Transport: handlerTransport{h: h}}))
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.ServerVersion(context.Background())
	if err != nil {
		t.Fatalf("ServerVersion: %v", err)
	}
	if info.SiteVersion != "" || info.APIVersion != "" || info.APIMode != "" {
		t.Fatalf("malicious version fields were not dropped: %+v", info)
	}

	// Trailing garbage after JSON object must fail closed.
	hTrailing := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"v1.0.0","api_origin":"same-origin"}{"extra":1}`))
	})
	c2, err := New("paste.example.test", WithHTTPClient(&http.Client{Transport: handlerTransport{h: hTrailing}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.ResolveAPIOrigin(context.Background()); err == nil {
		t.Fatal("expected trailing JSON data to be rejected")
	}
}

func TestClientRejectsSwappedBurnPrefix(t *testing.T) {
	ms := newMockServer()
	baseURL := "https://paste.example.test"
	baseHandler := ms.handler()

	// Create a normal burn paste first.
	c, err := New(baseURL, WithHTTPClient(&http.Client{Transport: handlerTransport{h: baseHandler}}))
	if err != nil {
		t.Fatal(err)
	}
	created, err := c.Create(context.Background(), CreateOptions{
		Text:      "burn payload",
		ExpiresIn: 300,
		Burn:      true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Now wrap the handler so GET /prefix returns a subtly different valid v1 prefix
	// while POST /read returns the real v2 blob.
	swappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/prefix") {
			fake := make([]byte, format.PrefixBytes)
			copy(fake[0:4], format.Magic[:])
			fake[4] = format.VersionUnpadded
			_, _ = w.Write(fake)
			return
		}
		baseHandler.ServeHTTP(w, r)
	})

	vl, err := link.ParseViewURL(created.ViewURL)
	if err != nil {
		t.Fatal(err)
	}
	defer vl.Close()

	cSwapped, err := New(baseURL, WithHTTPClient(&http.Client{Transport: handlerTransport{h: swappedHandler}}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cSwapped.Read(context.Background(), vl, ReadOptions{})
	var pe *format.PasteError
	if !errors.As(err, &pe) || pe.Code != format.CodeTampered {
		t.Fatalf("expected CodeTampered on prefix swap, got %v", err)
	}
}
