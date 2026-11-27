package fsutil

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingReader struct {
	prefix []byte
	sent   bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if !f.sent {
		f.sent = true
		n := copy(p, f.prefix)
		return n, nil
	}
	return 0, errors.New("tampered stream")
}

func TestSaveVerifiedStreamAtomicAndCleanup(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "secret.bin")

	// Failed stream must leave NO destination file and NO temp file behind.
	if _, err := SaveVerifiedStream(dest, false, &failingReader{prefix: []byte("unverified bytes")}); err == nil {
		t.Fatal("expected error from failingReader")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("destination should not exist after failed stream: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("leftover temp files in dir: %v", entries)
	}

	// Successful verified stream commits atomically.
	n, err := SaveVerifiedStream(dest, false, bytes.NewReader([]byte("verified payload")))
	if err != nil || n != 16 {
		t.Fatalf("SaveVerifiedStream: n=%d err=%v", n, err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "verified payload" {
		t.Fatalf("unexpected saved content: %q, %v", got, err)
	}

	// Refuses overwrite without --force.
	if _, err := SaveVerifiedStream(dest, false, strings.NewReader("overwrite")); err == nil {
		t.Fatal("expected overwrite refusal without --force")
	}

	// Allows overwrite with --force.
	if _, err := SaveVerifiedStream(dest, true, strings.NewReader("updated")); err != nil {
		t.Fatalf("SaveVerifiedStream --force: %v", err)
	}
	got, _ = os.ReadFile(dest)
	if string(got) != "updated" {
		t.Fatalf("got %q, want updated", got)
	}
}

func TestResolveOutputPathSanitizes(t *testing.T) {
	dir := t.TempDir()
	p, err := ResolveOutputPath(dir, "../../evil/invoice\u202Efdp.exe", "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p) != dir {
		t.Fatalf("escaped output dir: %s", p)
	}
	if strings.ContainsRune(filepath.Base(p), '\u202E') {
		t.Fatalf("bidi char remained in filename: %q", p)
	}
	_ = io.EOF
}
