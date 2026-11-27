package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConfigSaveLoadAndResolve(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Missing config returns empty config cleanly.
	cfg, err := Load(path)
	if err != nil || cfg.Server != "" {
		t.Fatalf("missing Load: %+v, %v", cfg, err)
	}

	// Save & Load round-trip.
	if err := Save(path, Config{Server: "https://paste.example.com/", API: "https://api.example.com"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Server != "https://paste.example.com" || loaded.API != "https://api.example.com" {
		t.Fatalf("unexpected loaded config: %+v", loaded)
	}

	// Unknown fields rejected.
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`{"server":"https://paste.example.com","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(badPath); err == nil {
		t.Fatal("expected error for unknown JSON field")
	}

	// Insecure permissions rejected on POSIX.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("expected error for 0644 config permissions")
		}
	}

	// Precedence: --server overrides config and does NOT inherit config.API.
	srv, api, err := ResolveServer("https://other.example", "", "", "", loaded)
	if err != nil || srv != "https://other.example" || api != "" {
		t.Fatalf("ResolveServer flag override = (%q, %q, %v)", srv, api, err)
	}

	// Fail closed when nothing is configured.
	if _, _, err := ResolveServer("", "", "", "", Config{}); err == nil {
		t.Fatal("expected error when no server is configured")
	}
}
