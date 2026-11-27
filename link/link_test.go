package link

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestValidateOrigin(t *testing.T) {
	good := map[string]string{
		"https://paste.example.com":      "https://paste.example.com",
		"https://PASTE.EXAMPLE.COM:443/": "https://paste.example.com",
		"https://paste.example.com:8443": "https://paste.example.com:8443",
		"http://localhost:8080":          "http://localhost:8080",
		"http://127.0.0.1:8080/":         "http://127.0.0.1:8080",
		"http://[::1]:8080":              "http://[::1]:8080",
		"http://localhost:80":            "http://localhost",
	}
	for in, want := range good {
		got, err := ValidateOrigin(in)
		if err != nil {
			t.Fatalf("ValidateOrigin(%q) error: %v", in, err)
		}
		if got != want {
			t.Fatalf("ValidateOrigin(%q) = %q, want %q", in, got, want)
		}
	}

	bad := []string{
		"",
		"http://paste.example.com",
		"http://192.168.1.1:8080",
		"ftp://paste.example.com",
		"https://user:pass@paste.example.com",
		"https://paste.example.com/subpath",
		"https://paste.example.com?a=1",
		"https://paste.example.com#frag",
		"https://paste.example.com:99999",
		"javascript:alert(1)",
	}
	for _, in := range bad {
		if got, err := ValidateOrigin(in); err == nil {
			t.Fatalf("ValidateOrigin(%q) = %q, want error", in, got)
		}
	}

	// ValidateCanonicalOrigin rejects trailing slash & HTTP when allowLoopbackHTTP=false.
	if _, err := ValidateCanonicalOrigin("https://api.example.com/", false); err == nil {
		t.Fatal("expected canonical origin to reject trailing slash")
	}
	if _, err := ValidateCanonicalOrigin("http://127.0.0.1:8080", false); err == nil {
		t.Fatal("expected canonical origin to reject loopback http when disallowed")
	}
	if got, err := ValidateCanonicalOrigin("http://127.0.0.1:8080", true); err != nil || got != "http://127.0.0.1:8080" {
		t.Fatalf("ValidateCanonicalOrigin loopback: %q, %v", got, err)
	}
}

func TestViewAndDeleteLinkRoundTrip(t *testing.T) {
	id := strings.Repeat("a", 32)
	key := bytes.Repeat([]byte{0x42}, 32)
	secret := bytes.Repeat([]byte{0x77}, 16)
	delTok := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, 32))

	u, err := FormatViewURL("https://paste.example.com", id, key, true, secret)
	if err != nil {
		t.Fatal(err)
	}
	vl, err := ParseViewURL(u)
	if err != nil {
		t.Fatalf("ParseViewURL: %v", err)
	}
	defer vl.Close()
	if vl.Origin != "https://paste.example.com" || vl.ID != id || !vl.Burn || !bytes.Equal(vl.Key, key) || !bytes.Equal(vl.RecipientSecret, secret) {
		t.Fatalf("unexpected ViewLink: %+v", vl)
	}

	// Non-canonical base64url (stray low bits in last char) must be rejected.
	// 32 bytes = 256 bits; 43 base64 chars = 258 bits; last 2 bits must be 0.
	nonCanonKey := strings.Repeat("A", 42) + "B" // 'B' has low bit 1
	if _, _, _, err := ParseKeyFragment(nonCanonKey); err == nil {
		t.Fatal("expected non-canonical base64url key to be rejected")
	}

	du, err := FormatDeleteURL("https://paste.example.com", id, delTok, true)
	if err != nil {
		t.Fatal(err)
	}
	dl, err := ParseDeleteURL(du)
	if err != nil {
		t.Fatalf("ParseDeleteURL: %v", err)
	}
	if dl.Origin != "https://paste.example.com" || dl.ID != id || dl.DeleteToken != delTok || !dl.HasRecipients {
		t.Fatalf("unexpected DeleteLink: %+v", dl)
	}

	// View fragment edited to /d/ must be rejected (no "d." prefix).
	if _, err := ParseDeleteURL("https://paste.example.com/d/" + id + "#" + delTok); err == nil {
		t.Fatal("expected delete link without d. prefix to be rejected")
	}
}

func FuzzParseLink(f *testing.F) {
	id := strings.Repeat("0", 32)
	k := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	f.Add("https://paste.example.com/p/" + id + "#" + k)
	f.Add("https://paste.example.com/d/" + id + "#d." + k + ".r")
	f.Add("http://evil.example/p/" + id + "#" + k)
	f.Fuzz(func(t *testing.T, s string) {
		if vl, err := ParseViewURL(s); err == nil {
			vl.Close()
		}
		_, _ = ParseDeleteURL(s)
		_, _ = ValidateOrigin(s)
	})
}
