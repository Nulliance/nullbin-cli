package tty

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestHasHiddenChars(t *testing.T) {
	if HasHiddenChars("plain ascii\n\tline 2\r\n") {
		t.Fatal("plain text flagged as hidden")
	}
	if HasHiddenChars("\uFEFFleading BOM is ok") {
		t.Fatal("leading BOM flagged as hidden")
	}
	if !HasHiddenChars("if (isAdmin\u202E/*)*/) return;") {
		t.Fatal("Trojan Source RLO not detected")
	}
	if !HasHiddenChars("invisible\u200Bspace") {
		t.Fatal("zero-width space not detected")
	}
	if !HasHiddenChars("bad\x1b[31mred\x1b[0m") {
		t.Fatal("ESC control sequence not detected")
	}
}

func TestSanitizeForTTY(t *testing.T) {
	// CSI + OSC 52 clipboard injection + standalone CR + bidi RLO.
	in := "safe\x1b[31mRED\x1b[0m\x1b]52;c;cHduZWQ=\x07\rspoof\u202Etxt\nline2"
	got, mod := SanitizeForTTY(in)
	if !mod {
		t.Fatal("expected modified=true")
	}
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\x07') || strings.ContainsRune(got, '\u202E') || strings.ContainsRune(got, '\r') {
		t.Fatalf("dangerous control or bidi survived sanitization: %q", got)
	}
	if !strings.Contains(got, "safeRED") || !strings.Contains(got, "\\r") || !strings.Contains(got, "\\u202E") || !strings.Contains(got, "\nline2") {
		t.Fatalf("unexpected sanitized output: %q", got)
	}

	plain, mod := SanitizeForTTY("hello\tworld\r\nline 2")
	if mod || plain != "hello\tworld\nline 2" {
		t.Fatalf("plain text unexpectedly modified: mod=%v out=%q", mod, plain)
	}

	// Invisible Hangul filler, CGJ, and Braille blank must also be visibly escaped.
	hidden, mod := SanitizeForTTY("a\u3164b\u034Fc\u2800d")
	if !mod || !strings.Contains(hidden, "\\u3164") || !strings.Contains(hidden, "\\u034F") || !strings.Contains(hidden, "\\u2800") {
		t.Fatalf("invisible fillers not escaped: mod=%v out=%q", mod, hidden)
	}

	single := SanitizeSingleLine("err\x1b[31m!\nsecond\tline")
	if strings.ContainsAny(single, "\x1b\n\t") || !strings.Contains(single, "\\n") {
		t.Fatalf("SanitizeSingleLine leaked control chars: %q", single)
	}
}

func TestReadBoundedLine(t *testing.T) {
	pw, err := ReadPasswordLine(strings.NewReader("my-secret-pass\r\nsecond-line\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pw) != "my-secret-pass" {
		t.Fatalf("got %q, want my-secret-pass", pw)
	}

	u, err := ReadURLLine(strings.NewReader("  https://paste.example.com/p/abc#xyz  \n"))
	if err != nil || u != "https://paste.example.com/p/abc#xyz" {
		t.Fatalf("ReadURLLine: %q, %v", u, err)
	}

	if _, err := ReadPasswordLine(zeroProgressReader{}); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("expected io.ErrNoProgress on stalled reader, got %v", err)
	}
}

type zeroProgressReader struct{}

func (zeroProgressReader) Read([]byte) (int, error) { return 0, nil }
