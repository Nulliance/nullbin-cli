package format

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	nbcrypto "github.com/Nulliance/nullbin-cli/crypto"
)

func TestPadmeEdgeSizes(t *testing.T) {
	cases := []struct {
		n    int64
		want int64
	}{
		{0, 16384},
		{1, 16384},
		{16384, 16384},
		{16385, 16384 + 1024},
		{32768, 32768},
		{32769, 32768 + 2048},
		{65535, 65536},
		{65536, 65536},
		{65537, 65536 + 2048},
		{100 * 1024 * 1024, 104857600},
	}
	for _, tc := range cases {
		got, err := PaddedLength(tc.n)
		if err != nil {
			t.Fatalf("PaddedLength(%d) error: %v", tc.n, err)
		}
		if got != tc.want {
			t.Fatalf("PaddedLength(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
	if _, err := PaddedLength(-1); err == nil {
		t.Fatal("expected error for negative length")
	}
	if _, err := PaddedLength(MaxStreamLength + 1); err == nil {
		t.Fatal("expected error for > MaxStreamLength")
	}
}

func TestV2TextAndFileRoundTripAndTamperRejection(t *testing.T) {
	frag := bytes.Repeat([]byte{0x7A}, KeyBytes)
	salt := make([]byte, SaltBytes)
	prefix, err := BuildPrefix(false, salt)
	if err != nil {
		t.Fatal(err)
	}
	streamKey, err := nbcrypto.DeriveStreamKey(frag)
	if err != nil {
		t.Fatal(err)
	}
	defer nbcrypto.Zero(streamKey)

	// Text paste round-trip.
	textMeta := PasteMeta{Type: "text", Text: "Hello, Nullbin! 🔐", Discussion: true}
	enc, totalSize, err := NewV2EncryptReader(streamKey, prefix, textMeta, nil)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := io.ReadAll(enc)
	_ = enc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(blob)) != totalSize {
		t.Fatalf("blob len = %d, want %d", len(blob), totalSize)
	}

	opened, err := OpenBlob(bytes.NewReader(blob), frag, nil)
	if err != nil {
		t.Fatalf("OpenBlob text: %v", err)
	}
	defer opened.Close()
	if opened.Meta.Type != "text" || opened.Meta.Text != textMeta.Text || !opened.Meta.Discussion {
		t.Fatalf("unexpected text meta: %+v", opened.Meta)
	}
	if opened.CommentToken == "" || len(opened.CommentKey) != KeyBytes {
		t.Fatal("expected discussion token and key")
	}

	// Trailing byte must be rejected.
	withTrailing := append(append([]byte(nil), blob...), 0x00)
	if _, err := OpenBlob(bytes.NewReader(withTrailing), frag, nil); err == nil {
		t.Fatal("expected error on trailing byte")
	}

	// Truncation must be rejected.
	if _, err := OpenBlob(bytes.NewReader(blob[:len(blob)-1]), frag, nil); err == nil {
		t.Fatal("expected error on truncated blob")
	}

	// Prefix tamper must be rejected (AAD).
	tamperedPrefix := append([]byte(nil), blob...)
	tamperedPrefix[5] ^= 0x01 // flip password flag
	if _, err := OpenBlob(bytes.NewReader(tamperedPrefix), frag, nil); err == nil {
		t.Fatal("expected error on tampered prefix")
	}

	// Multi-frame file paste (> 64 KiB) round-trip.
	payload := bytes.Repeat([]byte("0123456789abcdef"), 6000) // 96,000 bytes
	fname := "report.bin"
	mime := "application/octet-stream"
	fileMeta := PasteMeta{Type: "file", Text: "notes", Filename: &fname, Mime: &mime, Size: int64(len(payload))}
	encFile, fileBlobSize, err := NewV2EncryptReader(streamKey, prefix, fileMeta, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	fileBlob, err := io.ReadAll(encFile)
	_ = encFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(fileBlob)) != fileBlobSize {
		t.Fatalf("file blob size = %d, want %d", len(fileBlob), fileBlobSize)
	}

	openedFile, err := OpenBlob(bytes.NewReader(fileBlob), frag, nil)
	if err != nil {
		t.Fatalf("OpenBlob file: %v", err)
	}
	defer openedFile.Close()
	gotPayload, err := io.ReadAll(openedFile.File)
	if err != nil {
		t.Fatalf("read file stream: %v", err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatal("decrypted file payload mismatch")
	}
}

func TestV2NonZeroPaddingRejected(t *testing.T) {
	frag := bytes.Repeat([]byte{0x55}, KeyBytes)
	salt := make([]byte, SaltBytes)
	prefix, _ := BuildPrefix(false, salt)
	streamKey, _ := nbcrypto.DeriveStreamKey(frag)
	defer nbcrypto.Zero(streamKey)

	metaBytes, err := EncodeMeta(PasteMeta{Type: "text", Text: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, MinPaddedLength)
	binary.BigEndian.PutUint32(plain[0:4], uint32(len(metaBytes)))
	copy(plain[4:], metaBytes)
	plain[len(plain)-1] = 0x01 // non-zero padding byte!

	st, header, err := nbcrypto.InitPush(streamKey)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := st.Push(plain, prefix, nbcrypto.TagFinal)
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	blob.Write(prefix)
	blob.Write(header[:])
	var flen [4]byte
	binary.BigEndian.PutUint32(flen[:], uint32(len(ct)))
	blob.Write(flen[:])
	blob.Write(ct)

	_, err = OpenBlob(bytes.NewReader(blob.Bytes()), frag, nil)
	var pe *PasteError
	if !errors.As(err, &pe) || pe.Code != CodeFormat {
		t.Fatalf("expected format error for non-zero padding, got %v", err)
	}
}

func TestV1ReadOnlySupport(t *testing.T) {
	frag := bytes.Repeat([]byte{0x99}, KeyBytes)
	salt := make([]byte, SaltBytes)
	prefix := make([]byte, PrefixBytes)
	copy(prefix[0:4], Magic[:])
	prefix[4] = VersionUnpadded
	prefix[5] = 0
	copy(prefix[6:], salt)

	streamKey, _ := nbcrypto.DeriveStreamKey(frag)
	defer nbcrypto.Zero(streamKey)

	// V1 text paste.
	metaBytes, _ := EncodeMeta(PasteMeta{Type: "text", Text: "legacy v1 text"})
	st, hdr, err := nbcrypto.InitPush(streamKey)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := st.Push(metaBytes, prefix, nbcrypto.TagFinal)
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	buf.Write(prefix)
	buf.Write(hdr[:])
	var flen [4]byte
	binary.BigEndian.PutUint32(flen[:], uint32(len(ct)))
	buf.Write(flen[:])
	buf.Write(ct)

	opened, err := OpenBlob(bytes.NewReader(buf.Bytes()), frag, nil)
	if err != nil {
		t.Fatalf("OpenBlob v1 text: %v", err)
	}
	defer opened.Close()
	if opened.Meta.Text != "legacy v1 text" || opened.Prefix.Version != 1 {
		t.Fatalf("unexpected v1 result: %+v", opened)
	}

	// Future blob version (> 2) and unknown flags should suggest updating nullbin-cli.
	futurePrefix := make([]byte, PrefixBytes)
	copy(futurePrefix[0:4], Magic[:])
	futurePrefix[4] = 3
	if _, err := ParsePrefix(futurePrefix); err == nil || !strings.Contains(err.Error(), "update") {
		t.Fatalf("expected update hint for v3 prefix, got %v", err)
	}
	unknownFlagPrefix := make([]byte, PrefixBytes)
	copy(unknownFlagPrefix[0:4], Magic[:])
	unknownFlagPrefix[4] = Version
	unknownFlagPrefix[5] = 0x02
	if _, err := ParsePrefix(unknownFlagPrefix); err == nil || !strings.Contains(err.Error(), "update") {
		t.Fatalf("expected update hint for unknown flag bit, got %v", err)
	}
}

func TestStoredZipDeterministicAndCleanNames(t *testing.T) {
	if got := CleanFileName("../../evil\\invoice\u202Efdp.exe", "download"); strings.ContainsAny(got, `/\`) || strings.ContainsRune(got, '\u202E') {
		t.Fatalf("unsafe filename leaked: %q", got)
	}
	if got := CleanFileName("CON.txt", "download"); got != "_CON.txt" {
		t.Fatalf("Windows device name not prefixed: %q", got)
	}
	if got := CleanFileName("...hidden...", "download"); got != "hidden" {
		t.Fatalf("leading/trailing dots not stripped: %q", got)
	}
	if got := CleanFileName("...", "download"); got != "download" {
		t.Fatalf("expected fallback, got %q", got)
	}

	z, err := NewStoredZip([]ZipInput{
		{Name: "notes.txt", Size: 5, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("hello")), nil }},
		{Name: "NOTES.TXT", Size: 5, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("world")), nil }},
	})
	if err != nil {
		t.Fatalf("NewStoredZip: %v", err)
	}
	rc := z.Open()
	data, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) != z.Size() {
		t.Fatalf("zip size = %d, want %d", len(data), z.Size())
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	if len(zr.File) != 2 {
		t.Fatalf("entries = %d, want 2", len(zr.File))
	}
	if zr.File[0].Name != "notes.txt" || zr.File[1].Name != "NOTES (2).TXT" {
		t.Fatalf("unexpected deduped names: %q, %q", zr.File[0].Name, zr.File[1].Name)
	}
	for _, f := range zr.File {
		if f.Method != zip.Store {
			t.Fatalf("entry %q method = %d, want Store", f.Name, f.Method)
		}
		if f.Mode() != 0o644 {
			t.Fatalf("entry %q mode = %o, want 0644", f.Name, f.Mode())
		}
		if len(f.Extra) != 0 {
			t.Fatalf("entry %q has unexpected extra fields", f.Name)
		}
	}
}

func TestStoredZipRejectsInPlaceContentMutation(t *testing.T) {
	opens := 0
	z, err := NewStoredZip([]ZipInput{
		{
			Name: "a.txt",
			Size: 5,
			Open: func() (io.ReadCloser, error) {
				opens++
				if opens == 1 {
					return io.NopCloser(strings.NewReader("hello")), nil
				}
				return io.NopCloser(strings.NewReader("HELLO")), nil // same size, mutated content
			},
		},
		{
			Name: "b.txt",
			Size: 5,
			Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("world")), nil },
		},
	})
	if err != nil {
		t.Fatalf("NewStoredZip: %v", err)
	}
	rc := z.Open()
	defer rc.Close()
	if _, err := io.ReadAll(rc); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected CRC mismatch error on same-size mutation, got %v", err)
	}
}

func TestZeroLengthReadsAndZeroByteFileGrowth(t *testing.T) {
	// Zero-length Read must return (0, nil) without hanging on StoredZip.
	z, err := NewStoredZip([]ZipInput{
		{Name: "a.txt", Size: 3, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("abc")), nil }},
		{Name: "b.txt", Size: 3, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("def")), nil }},
	})
	if err != nil {
		t.Fatal(err)
	}
	zrc := z.Open()
	defer zrc.Close()
	if n, err := zrc.Read(nil); n != 0 || err != nil {
		t.Fatalf("StoredZip Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if _, err := io.ReadAll(zrc); err != nil {
		t.Fatalf("StoredZip ReadAll after Read(nil): %v", err)
	}

	// Zero-length Read on V2EncryptReader and v2FileReader must not hang or corrupt data.
	frag := bytes.Repeat([]byte{0x42}, KeyBytes)
	prefix, err := BuildPrefix(false, make([]byte, SaltBytes))
	if err != nil {
		t.Fatal(err)
	}
	streamKey, err := nbcrypto.DeriveStreamKey(frag)
	if err != nil {
		t.Fatal(err)
	}
	defer nbcrypto.Zero(streamKey)

	fname := "sample.bin"
	payload := []byte("payload-bytes")
	enc, _, err := NewV2EncryptReader(streamKey, prefix, PasteMeta{Type: "file", Filename: &fname, Size: int64(len(payload))}, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := enc.Read(nil); n != 0 || err != nil {
		t.Fatalf("V2EncryptReader Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	blob, err := io.ReadAll(enc)
	_ = enc.Close()
	if err != nil {
		t.Fatal(err)
	}

	opened, err := OpenBlob(bytes.NewReader(blob), frag, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if n, err := opened.File.Read(nil); n != 0 || err != nil {
		t.Fatalf("v2FileReader Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	got, err := io.ReadAll(opened.File)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("v2FileReader mismatch: %q, %v", got, err)
	}

	// Zero-byte file that grew before reading must fail closed.
	emptyName := "empty.txt"
	encZero, _, err := NewV2EncryptReader(streamKey, prefix, PasteMeta{Type: "file", Filename: &emptyName, Size: 0}, strings.NewReader("unexpected-byte"))
	if err != nil {
		t.Fatal(err)
	}
	defer encZero.Close()
	if _, err := io.ReadAll(encZero); err == nil || !strings.Contains(err.Error(), "grew") {
		t.Fatalf("expected file grew error for 0-byte file with data, got %v", err)
	}
}

func FuzzParsePrefix(f *testing.F) {
	f.Add([]byte("NBN1\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Add([]byte("NBN1\x02\x010123456789abcdef"))
	f.Add([]byte("NBN1\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Add([]byte("BAD!"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePrefix(data)
	})
}

func FuzzDecodeBlob(f *testing.F) {
	f.Add([]byte("NBN1\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Add([]byte{})
	key := bytes.Repeat([]byte{0x11}, KeyBytes)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256*1024 {
			return
		}
		opened, err := OpenBlob(bytes.NewReader(data), key, nil)
		if err == nil && opened != nil {
			if opened.File != nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(opened.File, 1024*1024))
			}
			_ = opened.Close()
		}
	})
}

func FuzzSanitizeFilename(f *testing.F) {
	f.Add("../../etc/passwd")
	f.Add("invoice\u202Efdp.exe")
	f.Add("CON.txt")
	f.Add("...   ...")
	f.Fuzz(func(t *testing.T, s string) {
		got := CleanFileName(s, "download")
		if got == "" {
			t.Fatal("CleanFileName returned empty string")
		}
		if strings.ContainsAny(got, `/\`) {
			t.Fatalf("CleanFileName returned path separator: %q", got)
		}
		if strings.HasPrefix(got, ".") {
			t.Fatalf("CleanFileName returned leading dot: %q", got)
		}
	})
}
