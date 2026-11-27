package format_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nbcrypto "github.com/Nulliance/nullbin-cli/crypto"
	"github.com/Nulliance/nullbin-cli/format"
	"github.com/Nulliance/nullbin-cli/link"
)

type canonicalVectors struct {
	GeneratedFrom string `json:"generated_from"`
	KDF           struct {
		MasterHex          string            `json:"master_hex"`
		SaltHex            string            `json:"salt_hex"`
		RecipientSecretHex string            `json:"recipient_secret_hex"`
		Subkeys            map[string]string `json:"subkeys"`
		BurnToken          string            `json:"burn_token"`
		CommentToken       string            `json:"comment_token"`
		CommentKeyHex      string            `json:"comment_key_hex"`
		RecipientToken     string            `json:"recipient_token"`
		PasswordNFC        string            `json:"password_nfc"`
		PasswordNFD        string            `json:"password_nfd"`
		DerivedMasterHex   string            `json:"derived_master_hex"`
	} `json:"kdf"`
	Padme []struct {
		N        int64 `json:"n"`
		Padded   int64 `json:"padded"`
		BlobSize int64 `json:"blob_size"`
	} `json:"padme"`
	V2Text struct {
		FragmentKeyHex       string `json:"fragment_key_hex"`
		ExpectedText         string `json:"expected_text"`
		ExpectedDiscussion   bool   `json:"expected_discussion"`
		ExpectedCommentToken string `json:"expected_comment_token"`
		ExpectedBurnToken    string `json:"expected_burn_token"`
		TotalSize            int64  `json:"total_size"`
		BlobB64              string `json:"blob_b64"`
	} `json:"v2_text"`
	V2PasswordRecipients struct {
		FragmentKeyHex      string   `json:"fragment_key_hex"`
		PasswordNFC         string   `json:"password_nfc"`
		PasswordNFD         string   `json:"password_nfd"`
		ExpectedText        string   `json:"expected_text"`
		ExpectedBurnToken   string   `json:"expected_burn_token"`
		RecipientSecretsHex []string `json:"recipient_secrets_hex"`
		RecipientTokens     []string `json:"recipient_tokens"`
		TotalSize           int64    `json:"total_size"`
		BlobB64             string   `json:"blob_b64"`
	} `json:"v2_password_recipients"`
	V2File struct {
		FragmentKeyHex  string `json:"fragment_key_hex"`
		ExpectedText    string `json:"expected_text"`
		ExpectedFile    string `json:"expected_filename"`
		ExpectedMime    string `json:"expected_mime"`
		ExpectedFileB64 string `json:"expected_file_b64"`
		TotalSize       int64  `json:"total_size"`
		BlobB64         string `json:"blob_b64"`
	} `json:"v2_file"`
	V1Text struct {
		FragmentKeyHex string `json:"fragment_key_hex"`
		ExpectedText   string `json:"expected_text"`
		BlobB64        string `json:"blob_b64"`
	} `json:"v1_text"`
	V1File struct {
		FragmentKeyHex  string `json:"fragment_key_hex"`
		ExpectedText    string `json:"expected_text"`
		ExpectedFile    string `json:"expected_filename"`
		ExpectedFileB64 string `json:"expected_file_b64"`
		BlobB64         string `json:"blob_b64"`
	} `json:"v1_file"`
	Zip struct {
		ArchiveName string `json:"archive_name"`
		ZipB64      string `json:"zip_b64"`
	} `json:"zip"`
	Links struct {
		Shared           string `json:"shared"`
		Burn             string `json:"burn"`
		Recipient        string `json:"recipient"`
		BurnRecipient    string `json:"burn_recipient"`
		Delete           string `json:"delete"`
		DeleteRecipients string `json:"delete_recipients"`
	} `json:"links"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return b
}

func TestCanonicalLibsodiumVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", "nullbin_vectors.json"))
	if err != nil {
		t.Fatalf("read canonical vectors: %v", err)
	}
	var v canonicalVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal canonical vectors: %v", err)
	}

	// 1. KDF, subkeys, burn/comment/recipient tokens, and Argon2id + NFC
	t.Run("KDFAndTokens", func(t *testing.T) {
		master := mustHex(t, v.KDF.MasterHex)
		salt := mustHex(t, v.KDF.SaltHex)
		rcptSecret := mustHex(t, v.KDF.RecipientSecretHex)

		for ctx, wantHex := range v.KDF.Subkeys {
			got, err := nbcrypto.DeriveSubkey(master, 1, ctx)
			if err != nil {
				t.Fatalf("DeriveSubkey(%s): %v", ctx, err)
			}
			if hex.EncodeToString(got) != wantHex {
				t.Fatalf("subkey(%s) mismatch:\ngot:  %x\nwant: %s", ctx, got, wantHex)
			}
		}

		burnTok, err := nbcrypto.DeriveBurnToken(master)
		if err != nil || burnTok != v.KDF.BurnToken {
			t.Fatalf("burn token = %q (%v), want %q", burnTok, err, v.KDF.BurnToken)
		}
		cmtTok, err := nbcrypto.DeriveCommentToken(master)
		if err != nil || cmtTok != v.KDF.CommentToken {
			t.Fatalf("comment token = %q (%v), want %q", cmtTok, err, v.KDF.CommentToken)
		}
		cmtKey, err := nbcrypto.DeriveCommentKey(master)
		if err != nil || hex.EncodeToString(cmtKey) != v.KDF.CommentKeyHex {
			t.Fatalf("comment key mismatch")
		}
		rcptTok, err := nbcrypto.DeriveRecipientToken(master, rcptSecret)
		if err != nil || rcptTok != v.KDF.RecipientToken {
			t.Fatalf("recipient token = %q (%v), want %q", rcptTok, err, v.KDF.RecipientToken)
		}

		// Both NFC and NFD passwords must match libsodium Argon2id + BLAKE2b output.
		for _, pw := range []string{v.KDF.PasswordNFC, v.KDF.PasswordNFD} {
			pwBuf := []byte(pw)
			gotMaster, err := nbcrypto.DeriveMasterKey(master, pwBuf, salt)
			if err != nil {
				t.Fatalf("DeriveMasterKey: %v", err)
			}
			// Caller's password slice must NOT be mutated by DeriveMasterKey.
			if string(pwBuf) != pw {
				t.Fatal("DeriveMasterKey mutated caller password slice")
			}
			if hex.EncodeToString(gotMaster) != v.KDF.DerivedMasterHex {
				t.Fatalf("Argon2id+NFC master mismatch:\ngot:  %x\nwant: %s", gotMaster, v.KDF.DerivedMasterHex)
			}
		}
	})

	// 2. Padmé edge sizes
	t.Run("Padme", func(t *testing.T) {
		for _, tc := range v.Padme {
			got, err := format.PaddedLength(tc.N)
			if err != nil {
				t.Fatalf("PaddedLength(%d): %v", tc.N, err)
			}
			if got != tc.Padded {
				t.Fatalf("PaddedLength(%d) = %d, want %d", tc.N, got, tc.Padded)
			}
			if bs := format.BlobSize(got); bs != tc.BlobSize {
				t.Fatalf("BlobSize(%d) = %d, want %d", got, bs, tc.BlobSize)
			}
		}
	})

	// 3. v2 text paste (no password, with discussion)
	t.Run("V2Text", func(t *testing.T) {
		key := mustHex(t, v.V2Text.FragmentKeyHex)
		blob := mustB64(t, v.V2Text.BlobB64)
		if int64(len(blob)) != v.V2Text.TotalSize {
			t.Fatalf("blob len = %d, want %d", len(blob), v.V2Text.TotalSize)
		}
		opened, err := format.OpenBlob(bytes.NewReader(blob), key, nil)
		if err != nil {
			t.Fatalf("OpenBlob v2 text: %v", err)
		}
		defer opened.Close()
		if opened.Meta.Text != v.V2Text.ExpectedText || opened.Meta.Discussion != v.V2Text.ExpectedDiscussion {
			t.Fatalf("unexpected v2 text meta: %+v", opened.Meta)
		}
		if opened.CommentToken != v.V2Text.ExpectedCommentToken {
			t.Fatalf("comment token = %q, want %q", opened.CommentToken, v.V2Text.ExpectedCommentToken)
		}
		if opened.BlobSize != v.V2Text.TotalSize {
			t.Fatalf("BlobSize = %d, want %d", opened.BlobSize, v.V2Text.TotalSize)
		}

		// Tampering any byte or truncating must fail.
		tampered := append([]byte(nil), blob...)
		tampered[len(tampered)-1] ^= 0x80
		if _, err := format.OpenBlob(bytes.NewReader(tampered), key, nil); err == nil {
			t.Fatal("expected tamper failure")
		}
		if _, err := format.OpenBlob(bytes.NewReader(blob[:len(blob)-1]), key, nil); err == nil {
			t.Fatal("expected truncation failure")
		}
	})

	// 4. v2 password-protected paste with separate recipients (NFC/NFD)
	t.Run("V2PasswordRecipients", func(t *testing.T) {
		key := mustHex(t, v.V2PasswordRecipients.FragmentKeyHex)
		blob := mustB64(t, v.V2PasswordRecipients.BlobB64)
		prefix, err := format.ParsePrefix(blob[:format.PrefixBytes])
		if err != nil || !prefix.Password {
			t.Fatalf("ParsePrefix: %+v, %v", prefix, err)
		}
		master, err := nbcrypto.DeriveMasterKey(key, []byte(v.V2PasswordRecipients.PasswordNFC), prefix.Salt[:])
		if err != nil {
			t.Fatal(err)
		}
		defer nbcrypto.Zero(master)

		if bt, err := nbcrypto.DeriveBurnToken(master); err != nil || bt != v.V2PasswordRecipients.ExpectedBurnToken {
			t.Fatalf("burn token mismatch: got %q, want %q", bt, v.V2PasswordRecipients.ExpectedBurnToken)
		}
		for i, secHex := range v.V2PasswordRecipients.RecipientSecretsHex {
			rt, err := nbcrypto.DeriveRecipientToken(master, mustHex(t, secHex))
			if err != nil || rt != v.V2PasswordRecipients.RecipientTokens[i] {
				t.Fatalf("recipient %d token = %q (%v), want %q", i, rt, err, v.V2PasswordRecipients.RecipientTokens[i])
			}
		}

		opened, err := format.OpenBlob(bytes.NewReader(blob), key, func(attempt int, _ [format.SaltBytes]byte) ([]byte, error) {
			if attempt == 0 {
				return []byte(v.V2PasswordRecipients.PasswordNFC), nil
			}
			return nil, format.ErrCancelled
		})
		if err != nil {
			t.Fatalf("OpenBlob v2 password: %v", err)
		}
		defer opened.Close()
		if opened.Meta.Text != v.V2PasswordRecipients.ExpectedText {
			t.Fatalf("text = %q, want %q", opened.Meta.Text, v.V2PasswordRecipients.ExpectedText)
		}
	})

	// 5. v2 multi-frame file paste (> 64 KiB)
	t.Run("V2MultiFrameFile", func(t *testing.T) {
		key := mustHex(t, v.V2File.FragmentKeyHex)
		blob := mustB64(t, v.V2File.BlobB64)
		wantFile := mustB64(t, v.V2File.ExpectedFileB64)

		opened, err := format.OpenBlob(bytes.NewReader(blob), key, nil)
		if err != nil {
			t.Fatalf("OpenBlob v2 file: %v", err)
		}
		defer opened.Close()
		if opened.Meta.Type != "file" || opened.Meta.Text != v.V2File.ExpectedText || opened.Meta.Filename == nil || *opened.Meta.Filename != v.V2File.ExpectedFile {
			t.Fatalf("unexpected v2 file meta: %+v", opened.Meta)
		}
		gotFile, err := io.ReadAll(opened.File)
		if err != nil {
			t.Fatalf("read v2 file stream: %v", err)
		}
		if !bytes.Equal(gotFile, wantFile) {
			t.Fatal("v2 decrypted file bytes mismatch")
		}
	})

	// 6. v1 read-only text & multi-frame file pastes
	t.Run("V1ReadOnly", func(t *testing.T) {
		openedText, err := format.OpenBlob(bytes.NewReader(mustB64(t, v.V1Text.BlobB64)), mustHex(t, v.V1Text.FragmentKeyHex), nil)
		if err != nil {
			t.Fatalf("OpenBlob v1 text: %v", err)
		}
		defer openedText.Close()
		if openedText.Prefix.Version != 1 || openedText.Meta.Text != v.V1Text.ExpectedText {
			t.Fatalf("unexpected v1 text: %+v", openedText)
		}

		openedFile, err := format.OpenBlob(bytes.NewReader(mustB64(t, v.V1File.BlobB64)), mustHex(t, v.V1File.FragmentKeyHex), nil)
		if err != nil {
			t.Fatalf("OpenBlob v1 file: %v", err)
		}
		defer openedFile.Close()
		gotFile, err := io.ReadAll(openedFile.File)
		if err != nil {
			t.Fatalf("read v1 file stream: %v", err)
		}
		if !bytes.Equal(gotFile, mustB64(t, v.V1File.ExpectedFileB64)) {
			t.Fatal("v1 decrypted file bytes mismatch")
		}
	})

	// 7. Byte-for-byte deterministic ZIP archive compatibility with web/src/zip.ts
	t.Run("DeterministicZipByteForByte", func(t *testing.T) {
		if got := format.ArchiveName(3); got != v.Zip.ArchiveName {
			t.Fatalf("ArchiveName = %q, want %q", got, v.Zip.ArchiveName)
		}
		z, err := format.NewStoredZip([]format.ZipInput{
			{Name: "notes.txt", Size: 12, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("hello world\n")), nil }},
			{Name: "NOTES.TXT", Size: 11, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("second copy")), nil }},
			{Name: "CON.txt", Size: 11, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("device test")), nil }},
		})
		if err != nil {
			t.Fatalf("NewStoredZip: %v", err)
		}
		rc := z.Open()
		gotZip, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		wantZip := mustB64(t, v.Zip.ZipB64)
		if !bytes.Equal(gotZip, wantZip) {
			t.Fatalf("ZIP archive does not match web/src/zip.ts byte-for-byte (got %d bytes, want %d bytes)", len(gotZip), len(wantZip))
		}
	})

	// 8. Link fragment compatibility with web/src/link.ts
	t.Run("Links", func(t *testing.T) {
		master := mustHex(t, v.KDF.MasterHex)
		rcptSecret := mustHex(t, v.KDF.RecipientSecretHex)
		id := strings.Repeat("a", 32)
		origin := "https://paste.example.com"

		u, err := link.FormatViewURL(origin, id, master, true, rcptSecret)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(u, "#"+v.Links.BurnRecipient) {
			t.Fatalf("view URL fragment mismatch:\ngot:  %s\nwant: #%s", u, v.Links.BurnRecipient)
		}
		vl, err := link.ParseViewURL(u)
		if err != nil || !vl.Burn || !bytes.Equal(vl.Key, master) || !bytes.Equal(vl.RecipientSecret, rcptSecret) {
			t.Fatalf("ParseViewURL failed: %+v, %v", vl, err)
		}
		vl.Close()

		delTok := base64.RawURLEncoding.EncodeToString(master)
		du, err := link.FormatDeleteURL(origin, id, delTok, true)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(du, "#"+v.Links.DeleteRecipients) {
			t.Fatalf("delete URL fragment mismatch:\ngot:  %s\nwant: #%s", du, v.Links.DeleteRecipients)
		}
	})
}
