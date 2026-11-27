package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/text/unicode/norm"
)

const (
	// KeyBytes is the length in bytes of fragment keys, master keys, and subkeys.
	KeyBytes = 32
	// SaltBytes is the length in bytes of the Argon2id salt.
	SaltBytes = 16
	// RecipientSecretBytes is the length in bytes of each recipient link secret.
	RecipientSecretBytes = 16

	// MinPasswordLength is the minimum accepted password length (matches web UI).
	MinPasswordLength = 8

	// Argon2id parameters matching libsodium OPSLIMIT_MODERATE / MEMLIMIT_MODERATE / ALG_ARGON2ID13.
	argon2Time    = 3
	argon2Memory  = 256 * 1024 // 256 MiB in KiB
	argon2Threads = 1

	// KDF subkey contexts (exact 8-byte libsodium contexts).
	ContextStream      = "nbstream"
	ContextCommentEnc  = "nbcmtenc"
	ContextCommentAcc  = "nbcmtacc"
	ContextBurnAcc     = "nbburnac"
	ContextRecipientAc = "nbrcptac"

	// Password generation parameters matching Nullbin web UI (56 unambiguous chars, ~116 bits).
	generatedPasswordChars  = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	GeneratedPasswordLength = 20
)

var (
	ErrInvalidSalt            = errors.New("crypto: invalid salt length")
	ErrInvalidContext         = errors.New("crypto: KDF context must be exactly 8 bytes")
	ErrInvalidRecipientSecret = errors.New("crypto: recipient secret must be 16 bytes")
	ErrPasswordTooShort       = errors.New("crypto: password must be at least 8 characters")
)

// RandomBytes fills a newly allocated slice of n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}

// GeneratePassword generates a 20-character password from the 56-character
// unambiguous Nullbin alphabet (~116 bits of entropy) using rejection sampling.
func GeneratePassword() ([]byte, error) {
	const alphabetLen = len(generatedPasswordChars)
	const limit = 256 - (256 % alphabetLen) // 224

	out := make([]byte, 0, GeneratedPasswordLength)
	var buf [32]byte
	defer clear(buf[:])

	for len(out) < GeneratedPasswordLength {
		if _, err := rand.Read(buf[:]); err != nil {
			clear(out)
			return nil, err
		}
		for _, b := range buf {
			if int(b) < limit && len(out) < GeneratedPasswordLength {
				out = append(out, generatedPasswordChars[int(b)%alphabetLen])
			}
		}
	}
	return out, nil
}

// ValidateNewPassword checks that a user-chosen password is valid UTF-8 and
// meets Nullbin's minimum length requirement (at least 8 characters).
func ValidateNewPassword(password []byte) error {
	if !utf8.Valid(password) {
		return errors.New("crypto: password must be valid UTF-8")
	}
	if utf8.RuneCount(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	return nil
}

// DeriveMasterKey derives the 32-byte master key from fragmentKey and an
// optional password. When password is empty, a copy of fragmentKey is returned.
// Otherwise password is normalized to Unicode NFC, stretched with Argon2id
// (v=0x13, time=3, mem=256 MiB, threads=1), and combined via
// BLAKE2b-256(key=fragmentKey, message=stretched).
func DeriveMasterKey(fragmentKey, password, salt []byte) ([]byte, error) {
	if len(fragmentKey) != KeyBytes {
		return nil, ErrInvalidKey
	}
	if len(salt) != SaltBytes {
		return nil, ErrInvalidSalt
	}
	if len(password) == 0 {
		master := make([]byte, KeyBytes)
		copy(master, fragmentKey)
		return master, nil
	}

	// Always allocate a fresh buffer so defer clear(nfc) never mutates caller's slice.
	nfc := norm.NFC.Append(make([]byte, 0, len(password)), password...)
	defer clear(nfc)

	stretched := argon2.IDKey(nfc, salt, argon2Time, argon2Memory, argon2Threads, KeyBytes)
	defer clear(stretched)

	h, err := blake2b.New256(fragmentKey)
	if err != nil {
		return nil, err
	}
	_, _ = h.Write(stretched)
	master := h.Sum(nil)
	return master, nil
}

// DeriveSubkey implements libsodium's crypto_kdf_derive_from_key(32, subkeyID, context, master).
func DeriveSubkey(master []byte, subkeyID uint64, context string) ([]byte, error) {
	if len(master) != KeyBytes {
		return nil, ErrInvalidKey
	}
	if len(context) != 8 {
		return nil, ErrInvalidContext
	}
	var salt [16]byte
	binary.LittleEndian.PutUint64(salt[0:8], subkeyID)

	var personal [16]byte
	copy(personal[0:8], context)

	digest, err := blake2b256SaltPersonal(master, nil, salt[:], personal[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, KeyBytes)
	copy(out, digest[:])
	clear(digest[:])
	return out, nil
}

// DeriveStreamKey derives the 32-byte paste encryption subkey ("nbstream", id=1).
func DeriveStreamKey(master []byte) ([]byte, error) {
	return DeriveSubkey(master, 1, ContextStream)
}

// DeriveBurnToken derives the 43-character unpadded base64url burn access token ("nbburnac", id=1).
func DeriveBurnToken(master []byte) (string, error) {
	b, err := DeriveSubkey(master, 1, ContextBurnAcc)
	if err != nil {
		return "", err
	}
	defer clear(b)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DeriveCommentToken derives the 43-character unpadded base64url comment access token ("nbcmtacc", id=1).
func DeriveCommentToken(master []byte) (string, error) {
	b, err := DeriveSubkey(master, 1, ContextCommentAcc)
	if err != nil {
		return "", err
	}
	defer clear(b)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DeriveCommentKey derives the 32-byte comment encryption key ("nbcmtenc", id=1).
func DeriveCommentKey(master []byte) ([]byte, error) {
	return DeriveSubkey(master, 1, ContextCommentEnc)
}

// DeriveRecipientToken derives the 43-character unpadded base64url access token
// for one separate recipient link:
// base64url(BLAKE2b-256(key=DeriveSubkey(master, 1, "nbrcptac"), message=secret)).
func DeriveRecipientToken(master, secret []byte) (string, error) {
	if len(secret) != RecipientSecretBytes {
		return "", ErrInvalidRecipientSecret
	}
	rcptKey, err := DeriveSubkey(master, 1, ContextRecipientAc)
	if err != nil {
		return "", err
	}
	defer clear(rcptKey)

	h, err := blake2b.New256(rcptKey)
	if err != nil {
		return "", err
	}
	_, _ = h.Write(secret)
	digest := h.Sum(nil)
	defer clear(digest)
	return base64.RawURLEncoding.EncodeToString(digest), nil
}
