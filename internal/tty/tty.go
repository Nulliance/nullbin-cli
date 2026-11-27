// Package tty handles interactive password prompts (echo off), file-descriptor
// secret reading, burn confirmations, Trojan Source / hidden character
// detection, and terminal escape-sequence sanitization.
package tty

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"

	nbcrypto "github.com/Nulliance/nullbin-cli/crypto"
)

const (
	// MaxJoinerChecks caps contextual ZWJ/ZWNJ/VS checks (matches web/src/hidden.ts).
	MaxJoinerChecks = 4096

	maxPasswordLineBytes = 4096
	maxURLLineBytes      = 16384
)

// IsTTY reports whether f is connected to an interactive terminal.
func IsTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// PromptPassword prompts on errOut and reads a password from in with terminal
// echo disabled. Fails closed if in is not a TTY.
func PromptPassword(prompt string, in *os.File, errOut io.Writer) ([]byte, error) {
	if !IsTTY(in) {
		return nil, errors.New("interactive password prompt requires a TTY (use --password-stdin or --password-fd)")
	}
	if _, err := io.WriteString(errOut, prompt); err != nil {
		return nil, err
	}
	pw, err := term.ReadPassword(int(in.Fd()))
	_, _ = io.WriteString(errOut, "\n")
	if err != nil {
		nbcrypto.Zero(pw)
		return nil, err
	}
	return pw, nil
}

// PromptNewPassword prompts twice with echo off, checks equality in constant
// time, and validates minimum length (>= 8 characters).
func PromptNewPassword(in *os.File, errOut io.Writer) ([]byte, error) {
	pw1, err := PromptPassword("Password: ", in, errOut)
	if err != nil {
		return nil, err
	}
	if err := nbcrypto.ValidateNewPassword(pw1); err != nil {
		nbcrypto.Zero(pw1)
		return nil, err
	}
	pw2, err := PromptPassword("Confirm password: ", in, errOut)
	if err != nil {
		nbcrypto.Zero(pw1)
		return nil, err
	}
	match := subtle.ConstantTimeCompare(pw1, pw2) == 1
	nbcrypto.Zero(pw2)
	if !match {
		nbcrypto.Zero(pw1)
		return nil, errors.New("passwords do not match")
	}
	return pw1, nil
}

// ReadPasswordLine reads a single password line (stripping trailing \r\n or \n)
// from r, bounded to maxPasswordLineBytes.
func ReadPasswordLine(r io.Reader) ([]byte, error) {
	return readBoundedLine(r, maxPasswordLineBytes)
}

// ReadURLLine reads a single URL line from r, bounded to maxURLLineBytes.
func ReadURLLine(r io.Reader) (string, error) {
	b, err := readBoundedLine(r, maxURLLineBytes)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	nbcrypto.Zero(b)
	if s == "" {
		return "", errors.New("no URL provided on stdin")
	}
	return s, nil
}

func readBoundedLine(r io.Reader, maxBytes int) ([]byte, error) {
	lr := io.LimitReader(r, int64(maxBytes)+2)
	br := bufio.NewReader(lr)
	line, err := br.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		nbcrypto.Zero(line)
		return nil, err
	}
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if len(line) > maxBytes {
		nbcrypto.Zero(line)
		return nil, fmt.Errorf("input line exceeds %d bytes", maxBytes)
	}
	return line, nil
}

// ReadPasswordFD reads a single password line from the given file descriptor.
func ReadPasswordFD(fd int) ([]byte, error) {
	if fd < 0 {
		return nil, errors.New("invalid password file descriptor")
	}
	f := os.NewFile(uintptr(fd), "password-fd")
	if f == nil {
		return nil, fmt.Errorf("could not open file descriptor %d", fd)
	}
	if fd >= 3 {
		defer f.Close()
	}
	return ReadPasswordLine(f)
}

// ConfirmBurn asks an interactive user to confirm before consuming an open on a
// burn-after-reading or limited recipient paste.
func ConfirmBurn(in *os.File, errOut io.Writer, isRecipient bool) (bool, error) {
	if !IsTTY(in) {
		return false, errors.New("refusing to consume a burn paste without a TTY confirmation (pass --yes to confirm)")
	}
	msg := "This paste burns after reading (opening consumes an open). Continue? [y/N]: "
	if isRecipient {
		msg = "This link has an open limit (opening consumes an open). Continue? [y/N]: "
	}
	if _, err := io.WriteString(errOut, msg); err != nil {
		return false, err
	}
	line, err := readBoundedLine(in, 64)
	if err != nil {
		return false, err
	}
	ans := strings.ToLower(strings.TrimSpace(string(line)))
	return ans == "y" || ans == "yes", nil
}

// HasHiddenChars reports whether text contains invisible, bidi, or
// Trojan-Source characters (CVE-2021-42574), mirroring web/src/hidden.ts.
func HasHiddenChars(text string) bool {
	// Allow a leading UTF-8 BOM.
	s := strings.TrimPrefix(text, "\uFEFF")

	// Strip legitimate UK subdivision flag tag sequences (England, Scotland, Wales).
	s = stripKnownFlagTags(s)

	runes := []rune(s)
	joinerChecks := 0

	for i, r := range runes {
		switch r {
		case '\t', '\n', '\r':
			continue
		case '\u200C', '\u200D', '\uFE0E', '\uFE0F':
			joinerChecks++
			if joinerChecks > MaxJoinerChecks {
				return true
			}
			if !joinerOK(runes, i) {
				return true
			}
			continue
		}
		if isHiddenTextRune(r) {
			return true
		}
	}
	return false
}

func stripKnownFlagTags(s string) string {
	// England, Scotland, Wales flag sequences.
	replacer := strings.NewReplacer(
		"\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F", "\U0001F3F4",
		"\U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F", "\U0001F3F4",
		"\U0001F3F4\U000E0067\U000E0062\U000E0077\U000E006C\U000E0073\U000E007F", "\U0001F3F4",
	)
	return replacer.Replace(s)
}

func isHiddenTextRune(r rune) bool {
	switch r {
	case 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0, 0x2800:
		return true
	}
	if (r >= 0x180B && r <= 0x180F) || (r >= 0xFE00 && r <= 0xFE0D) || (r >= 0xE0100 && r <= 0xE01EF) {
		return true
	}
	return unicode.Is(unicode.Cc, r) ||
		unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Zl, r) ||
		unicode.Is(unicode.Zp, r) ||
		unicode.Is(unicode.Cs, r) ||
		unicode.Is(unicode.Co, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

var joiningScripts = []*unicode.RangeTable{
	unicode.Arabic, unicode.Syriac, unicode.Nko, unicode.Devanagari,
	unicode.Bengali, unicode.Gurmukhi, unicode.Gujarati, unicode.Oriya,
	unicode.Tamil, unicode.Telugu, unicode.Kannada, unicode.Malayalam,
	unicode.Sinhala, unicode.Myanmar, unicode.Khmer, unicode.Tibetan,
	unicode.Thaana,
}

func isJoiningScript(r rune) bool {
	return unicode.In(r, joiningScripts...)
}

func isLikelyEmoji(r rune) bool {
	// Common emoji & pictograph ranges for ZWJ/VS15/VS16 validation.
	return (r >= 0x2300 && r <= 0x27BF) ||
		(r >= 0x2B00 && r <= 0x2BFF) ||
		(r >= 0x1F000 && r <= 0x1FAFF) ||
		r == 0x00A9 || r == 0x00AE || r == 0x203C || r == 0x2049 ||
		r == 0x2122 || r == 0x2139 || (r >= 0x2194 && r <= 0x21AA) ||
		r == 0x3030 || r == 0x303D || r == 0x3297 || r == 0x3299
}

func joinerOK(runes []rune, i int) bool {
	c := runes[i]
	var prev, next rune
	hasPrev := i > 0
	if hasPrev {
		prev = runes[i-1]
	}
	hasNext := i+1 < len(runes)
	if hasNext {
		next = runes[i+1]
	}
	if (c == '\u200C' || c == '\u200D') && (next == '\u200C' || next == '\u200D') {
		return false
	}
	switch c {
	case '\u200D':
		if hasPrev && hasNext && (isLikelyEmoji(prev) || prev == '\uFE0F') && isLikelyEmoji(next) {
			return true
		}
		if hasPrev && isJoiningScript(prev) {
			return !hasNext || isJoiningScript(next) || (!unicode.IsLetter(next) && !unicode.IsMark(next))
		}
		return false
	case '\u200C':
		return hasPrev && hasNext && isJoiningScript(prev) && isJoiningScript(next) && unicode.IsLetter(next)
	default: // FE0E, FE0F
		return hasPrev && isLikelyEmoji(prev) && prev != '\uFE0E' && prev != '\uFE0F'
	}
}

// SanitizeForTTY neutralizes ANSI/VT100/OSC/C0/C1 terminal control sequences
// and bidi/format/hidden characters when printing untrusted paste text to an
// interactive TTY. Returns the sanitized string and whether any escape or
// dangerous character was neutralized.
func SanitizeForTTY(text string) (string, bool) {
	var b strings.Builder
	b.Grow(len(text))
	modified := false

	for i := 0; i < len(text); {
		ch := text[i]

		// 7-bit ESC sequences (CSI, OSC, DCS/SOS/PM/APC, 2-byte ESC).
		if ch == 0x1b {
			modified = true
			i = skipEscapeSequence(text, i)
			continue
		}

		r, size := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && size == 1 {
			modified = true
			fmt.Fprintf(&b, "\\x%02x", ch)
			i++
			continue
		}

		// 8-bit C1 control characters (U+0080..U+009F), including 8-bit CSI/OSC.
		if r >= 0x80 && r <= 0x9F {
			modified = true
			if r == 0x9B { // 8-bit CSI
				i = skipCSIBody(text, i+size)
				continue
			}
			if r == 0x9D || r == 0x90 || r == 0x98 || r == 0x9E || r == 0x9F { // 8-bit OSC/DCS/SOS/PM/APC
				i = skipStringTerminated(text, i+size)
				continue
			}
			fmt.Fprintf(&b, "\\u%04X", r)
			i += size
			continue
		}

		// C0 control characters (keep \t and \n; turn \r into safe newline or escape).
		if r < 0x20 || r == 0x7F {
			switch r {
			case '\t', '\n':
				b.WriteRune(r)
			case '\r':
				// Allow CRLF cleanly, but escape standalone CR (which overwrites lines on a TTY).
				if i+1 < len(text) && text[i+1] == '\n' {
					// drop CR before LF
				} else {
					modified = true
					b.WriteString("\\r")
				}
			default:
				modified = true
				fmt.Fprintf(&b, "\\x%02x", r)
			}
			i += size
			continue
		}

		// Bidi controls and hidden format characters: render visibly so Trojan Source cannot spoof output.
		if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			modified = true
			if r <= 0xFFFF {
				fmt.Fprintf(&b, "\\u%04X", r)
			} else {
				fmt.Fprintf(&b, "\\U%08X", r)
			}
			i += size
			continue
		}

		b.WriteRune(r)
		i += size
	}

	return b.String(), modified
}

func skipEscapeSequence(s string, i int) int {
	// s[i] == 0x1b
	if i+1 >= len(s) {
		return i + 1
	}
	next := s[i+1]
	switch next {
	case '[': // CSI: ESC [ params intermediates final (0x40..0x7E)
		return skipCSIBody(s, i+2)
	case ']', 'P', 'X', '^', '_': // OSC, DCS, SOS, PM, APC terminated by BEL or ST (ESC \)
		return skipStringTerminated(s, i+2)
	default:
		// Two-byte or intermediate ESC sequence (0x20..0x2F intermediates then 0x30..0x7E).
		j := i + 1
		for j < len(s) && s[j] >= 0x20 && s[j] <= 0x2F {
			j++
		}
		if j < len(s) {
			return j + 1
		}
		return j
	}
}

func skipCSIBody(s string, j int) int {
	for j < len(s) {
		c := s[j]
		j++
		if c >= 0x40 && c <= 0x7E {
			return j
		}
	}
	return j
}

func skipStringTerminated(s string, j int) int {
	for j < len(s) {
		c := s[j]
		if c == 0x07 { // BEL
			return j + 1
		}
		if c == 0x1b && j+1 < len(s) && s[j+1] == '\\' { // ST
			return j + 2
		}
		// 8-bit ST (U+009C = 0xC2 0x9C)
		if c == 0xC2 && j+1 < len(s) && s[j+1] == 0x9C {
			return j + 2
		}
		j++
	}
	return j
}
