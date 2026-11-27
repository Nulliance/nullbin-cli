package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nulliance/nullbin-cli/format"
)

type cliMockPaste struct {
	id         string
	uploadTok  string
	deleteTok  string
	burn       bool
	burnHash   [32]byte
	chunks     bytes.Buffer
	finalized  bool
	recipients []struct {
		hash     [32]byte
		opens    int
		maxOpens *int
		revoked  bool
	}
}

type cliHandlerTransport struct {
	h http.Handler
}

func (ht cliHandlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	ht.h.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func newCLITestHandler(t *testing.T) http.Handler {
	t.Helper()
	var mu sync.Mutex
	pastes := map[string]*cliMockPaste{}
	randHex := func() string {
		var b [16]byte
		_, _ = rand.Read(b[:])
		return hex.EncodeToString(b[:])
	}
	randTok := func() string {
		var b [32]byte
		_, _ = rand.Read(b[:])
		return base64.RawURLEncoding.EncodeToString(b[:])
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /version.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "v1.0.0-test", "api_origin": "same-origin"})
	})
	mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "v1.0.0-test", "mode": "api"})
	})
	mux.HandleFunc("POST /api/v1/pastes", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			BurnAfterReading bool   `json:"burn_after_reading"`
			BurnToken        string `json:"burn_token"`
			Recipients       []struct {
				Token    string `json:"token"`
				MaxReads *int   `json:"max_reads"`
			} `json:"recipients"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		p := &cliMockPaste{
			id:        randHex(),
			uploadTok: randTok(),
			deleteTok: randTok(),
			burn:      body.BurnAfterReading,
		}
		if body.BurnToken != "" {
			p.burnHash = sha256.Sum256([]byte(body.BurnToken))
		}
		for _, rc := range body.Recipients {
			p.recipients = append(p.recipients, struct {
				hash     [32]byte
				opens    int
				maxOpens *int
				revoked  bool
			}{hash: sha256.Sum256([]byte(rc.Token)), maxOpens: rc.MaxReads})
		}
		mu.Lock()
		pastes[p.id] = p
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id": p.id, "upload_token": p.uploadTok, "delete_token": p.deleteTok,
		})
	})
	mux.HandleFunc("PUT /api/v1/pastes/{id}/chunks/{n}", func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		p := pastes[r.PathValue("id")]
		if p == nil || r.Header.Get("Nullbin-Upload-Token") != p.uploadTok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		p.chunks.Write(data)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/pastes/{id}/finalize", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := pastes[r.PathValue("id")]
		if p == nil || r.Header.Get("Nullbin-Upload-Token") != p.uploadTok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		p.finalized = true
		_ = json.NewEncoder(w).Encode(map[string]string{"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("GET /api/v1/pastes/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := pastes[r.PathValue("id")]
		if p == nil || !p.finalized || p.burn {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(p.chunks.Bytes())
	})
	mux.HandleFunc("GET /api/v1/pastes/{id}/prefix", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := pastes[r.PathValue("id")]
		if p == nil || !p.finalized || !p.burn {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(p.chunks.Bytes()[:format.PrefixBytes])
	})
	mux.HandleFunc("POST /api/v1/pastes/{id}/read", func(w http.ResponseWriter, r *http.Request) {
		h := sha256.Sum256([]byte(r.Header.Get("Nullbin-Burn-Token")))
		mu.Lock()
		defer mu.Unlock()
		p := pastes[r.PathValue("id")]
		if p == nil || !p.finalized || !p.burn {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if p.burnHash == h {
			w.Header().Set("Nullbin-Reads-Remaining", "0")
			data := append([]byte(nil), p.chunks.Bytes()...)
			delete(pastes, p.id)
			_, _ = w.Write(data)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("DELETE /api/v1/pastes/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := pastes[r.PathValue("id")]
		if p == nil || r.Header.Get("Nullbin-Delete-Token") != p.deleteTok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(pastes, p.id)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/pastes/{id}/recipients", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := pastes[r.PathValue("id")]
		if p == nil || r.Header.Get("Nullbin-Delete-Token") != p.deleteTok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		list := make([]map[string]any, len(p.recipients))
		for i, rc := range p.recipients {
			list[i] = map[string]any{"opens": rc.opens, "max_opens": rc.maxOpens, "revoked": rc.revoked}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"recipients": list})
	})
	mux.HandleFunc("POST /api/v1/pastes/{id}/recipients/{n}/revoke", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.PathValue("n"))
		mu.Lock()
		defer mu.Unlock()
		p := pastes[r.PathValue("id")]
		if p == nil || r.Header.Get("Nullbin-Delete-Token") != p.deleteTok || n < 0 || n >= len(p.recipients) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		p.recipients[n].revoked = true
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func runCLI(t *testing.T, hc *http.Client, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	app := &App{
		Build:      BuildInfo{Version: "test-v0.1.0"},
		StdinR:     strings.NewReader(stdin),
		Stdout:     &out,
		Stderr:     &errOut,
		Getenv:     func(string) string { return "" },
		ConfigPath: filepath.Join(t.TempDir(), "nonexistent.json"),
		HTTPClient: hc,
	}
	code := app.Run(context.Background(), args)
	return code, out.String(), errOut.String()
}

func TestCLICreateReadDeleteAndSecurityGuards(t *testing.T) {
	hc := &http.Client{Transport: cliHandlerTransport{h: newCLITestHandler(t)}}
	srvURL := "https://paste.example.test"

	// 1. Fail closed when no server is configured.
	code, _, errOut := runCLI(t, hc, "hello", "create")
	if code == 0 || !strings.Contains(errOut, "no Nullbin server configured") {
		t.Fatalf("expected fail-closed server error, got code=%d err=%q", code, errOut)
	}

	// 2. Reject --password with a positional secret in argv.
	code, _, _ = runCLI(t, hc, "hello", "create", "--server", srvURL, "--password", "secret-in-argv")
	if code == 0 {
		t.Fatal("expected rejection when passing secret after --password")
	}

	// 3. Create with generated password + file attachment (--json).
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "hello.txt")
	if err := os.WriteFile(srcFile, []byte("file contents 123"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, hc, "", "create", "--server", srvURL, "--text", "note text", "--file", srcFile, "--generate-password", "--json")
	if code != 0 {
		t.Fatalf("create failed (%d): %s", code, errOut)
	}
	var created struct {
		ViewURL           string `json:"view_url"`
		DeleteURL         string `json:"delete_url"`
		GeneratedPassword string `json:"generated_password"`
	}
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("parse create JSON: %v\n%s", err, out)
	}
	if created.ViewURL == "" || created.DeleteURL == "" || len(created.GeneratedPassword) != 20 {
		t.Fatalf("unexpected create output: %+v", created)
	}

	// 4. Read using --password-stdin and save attachment into --out-dir.
	outDir := t.TempDir()
	code, _, errOut = runCLI(t, hc, created.GeneratedPassword+"\n", "read", "--password-stdin", "--out-dir", outDir, "--json", created.ViewURL)
	if code != 0 {
		t.Fatalf("read failed (%d): %s", code, errOut)
	}
	saved, err := os.ReadFile(filepath.Join(outDir, "hello.txt"))
	if err != nil || string(saved) != "file contents 123" {
		t.Fatalf("saved file mismatch: %q, %v", saved, err)
	}

	// 5. Delete using --url-stdin.
	code, _, errOut = runCLI(t, hc, created.DeleteURL+"\n", "delete", "--url-stdin", "--json")
	if code != 0 {
		t.Fatalf("delete failed (%d): %s", code, errOut)
	}

	// 6. Burn paste refuses non-TTY without --yes, succeeds with --yes.
	code, out, errOut = runCLI(t, hc, "burn text", "create", "--server", srvURL, "--burn", "--json")
	if code != 0 {
		t.Fatalf("burn create failed: %s", errOut)
	}
	var burned struct {
		ViewURL string `json:"view_url"`
	}
	_ = json.Unmarshal([]byte(out), &burned)
	code, _, _ = runCLI(t, hc, "", "read", burned.ViewURL)
	if code == 0 {
		t.Fatal("expected burn read without --yes on non-TTY to refuse")
	}
	code, out, errOut = runCLI(t, hc, "", "read", "--yes", burned.ViewURL)
	if code != 0 || out != "burn text" {
		t.Fatalf("burn read --yes failed: code=%d out=%q err=%q", code, out, errOut)
	}

	// 7. Version command with --server.
	code, out, errOut = runCLI(t, hc, "", "version", "--server", srvURL, "--json")
	if code != 0 || !strings.Contains(out, "v1.0.0-test") {
		t.Fatalf("version failed: code=%d out=%q err=%q", code, out, errOut)
	}
}
