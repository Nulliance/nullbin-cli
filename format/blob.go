package format

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	nbcrypto "github.com/Nulliance/nullbin-cli/crypto"
)

// ErrorCode classifies paste parsing and decryption errors.
type ErrorCode string

const (
	CodeFormat        ErrorCode = "format"
	CodeTruncated     ErrorCode = "truncated"
	CodeTampered      ErrorCode = "tampered"
	CodeWrongKey      ErrorCode = "wrong-key"
	CodeWrongPassword ErrorCode = "wrong-password"
	CodeTooLarge      ErrorCode = "too-large"
	CodeCancelled     ErrorCode = "cancelled"
)

// PasteError is returned for protocol, format, authentication, or limit errors.
type PasteError struct {
	Code    ErrorCode
	Message string
}

func (e *PasteError) Error() string {
	return e.Message
}

func newErr(code ErrorCode, msg string) *PasteError {
	return &PasteError{Code: code, Message: msg}
}

// Prefix holds the parsed 22-byte public Nullbin blob header.
type Prefix struct {
	Version  byte
	Password bool
	Salt     [SaltBytes]byte
	Raw      [PrefixBytes]byte
}

// BuildPrefix builds the 22-byte v2 blob prefix.
func BuildPrefix(password bool, salt []byte) ([]byte, error) {
	if len(salt) != SaltBytes {
		return nil, newErr(CodeFormat, "invalid salt length")
	}
	if !password {
		for _, b := range salt {
			if b != 0 {
				return nil, newErr(CodeFormat, "salt must be all zeros without a password")
			}
		}
	}
	p := make([]byte, PrefixBytes)
	copy(p[0:4], Magic[:])
	p[4] = Version
	if password {
		p[5] = FlagPassword
	}
	copy(p[6:PrefixBytes], salt)
	return p, nil
}

// ParsePrefix strictly validates a 22-byte Nullbin blob prefix.
func ParsePrefix(p []byte) (Prefix, error) {
	var out Prefix
	if len(p) != PrefixBytes {
		return out, newErr(CodeFormat, "not a Nullbin paste")
	}
	if !bytes.Equal(p[0:4], Magic[:]) {
		return out, newErr(CodeFormat, "not a Nullbin paste")
	}
	version := p[4]
	if version != Version && version != VersionUnpadded {
		return out, newErr(CodeFormat, "unsupported paste format version")
	}
	flags := p[5]
	if (flags &^ KnownFlags) != 0 {
		return out, newErr(CodeFormat, "paste uses unknown header flags")
	}
	password := (flags & FlagPassword) != 0
	if !password {
		for _, b := range p[6:PrefixBytes] {
			if b != 0 {
				return out, newErr(CodeFormat, "malformed paste header")
			}
		}
	}
	out.Version = version
	out.Password = password
	copy(out.Salt[:], p[6:PrefixBytes])
	copy(out.Raw[:], p)
	return out, nil
}

// PasteMeta matches Nullbin's exact metadata JSON schema.
type PasteMeta struct {
	Type       string  `json:"type"`
	Text       string  `json:"text"`
	Filename   *string `json:"filename"`
	Mime       *string `json:"mime"`
	Size       int64   `json:"size"`
	Discussion bool    `json:"discussion"`
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// EncodeMeta validates and serializes PasteMeta without HTML escaping.
func EncodeMeta(m PasteMeta) ([]byte, error) {
	if m.Type == "text" {
		if m.Filename != nil || m.Mime != nil || m.Size != 0 {
			return nil, newErr(CodeFormat, "invalid text paste metadata")
		}
	} else if m.Type == "file" {
		if m.Filename == nil || *m.Filename == "" || utf16Len(*m.Filename) > MaxFilenameLength {
			return nil, newErr(CodeFormat, "invalid attachment filename")
		}
		if m.Mime != nil && utf16Len(*m.Mime) > MaxMimeLength {
			return nil, newErr(CodeFormat, "invalid attachment MIME type")
		}
		if m.Size < 0 || m.Size > MaxStreamLength {
			return nil, newErr(CodeTooLarge, "attachment size out of bounds")
		}
	} else {
		return nil, newErr(CodeFormat, "invalid paste type")
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	b := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(b) > MaxMetaBytes {
		return nil, newErr(CodeTooLarge, "paste text exceeds 16 MiB metadata limit")
	}
	return b, nil
}

// ParseMeta strictly parses and validates decrypted paste metadata JSON.
// It rejects non-UTF-8 bytes, duplicate keys, unknown keys, missing keys,
// wrong JSON types, non-integer sizes, and trailing tokens.
func ParseMeta(data []byte) (PasteMeta, error) {
	bad := func() (PasteMeta, error) {
		return PasteMeta{}, newErr(CodeFormat, "malformed paste metadata")
	}
	if !utf8.Valid(data) {
		return bad()
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return bad()
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return bad()
	}

	seen := make(map[string]bool, 6)
	var meta PasteMeta
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return bad()
		}
		key, ok := kt.(string)
		if !ok || seen[key] {
			return bad()
		}
		seen[key] = true

		val, err := dec.Token()
		if err != nil {
			return bad()
		}
		// Reject nested objects or arrays as field values.
		if _, isDelim := val.(json.Delim); isDelim {
			return bad()
		}

		switch key {
		case "type":
			s, ok := val.(string)
			if !ok {
				return bad()
			}
			meta.Type = s
		case "text":
			s, ok := val.(string)
			if !ok {
				return bad()
			}
			meta.Text = s
		case "filename":
			if val != nil {
				s, ok := val.(string)
				if !ok {
					return bad()
				}
				meta.Filename = &s
			}
		case "mime":
			if val != nil {
				s, ok := val.(string)
				if !ok {
					return bad()
				}
				meta.Mime = &s
			}
		case "size":
			num, ok := val.(json.Number)
			if !ok {
				return bad()
			}
			// Require a plain non-negative base-10 integer (no decimals/exponents).
			rawNum := num.String()
			if rawNum == "" || rawNum[0] == '-' {
				return bad()
			}
			for i := 0; i < len(rawNum); i++ {
				if rawNum[i] < '0' || rawNum[i] > '9' {
					return bad()
				}
			}
			sz, err := strconv.ParseInt(rawNum, 10, 64)
			if err != nil || sz < 0 || sz > MaxStreamLength {
				return bad()
			}
			meta.Size = sz
		case "discussion":
			b, ok := val.(bool)
			if !ok {
				return bad()
			}
			meta.Discussion = b
		default:
			return bad()
		}
	}

	endTok, err := dec.Token()
	if err != nil {
		return bad()
	}
	if d, ok := endTok.(json.Delim); !ok || d != '}' {
		return bad()
	}
	// Reject any trailing JSON tokens.
	if _, err := dec.Token(); err != io.EOF {
		return bad()
	}
	if len(seen) != 6 {
		return bad()
	}

	switch meta.Type {
	case "text":
		if meta.Filename != nil || meta.Mime != nil || meta.Size != 0 {
			return bad()
		}
		return meta, nil
	case "file":
		if meta.Filename == nil || *meta.Filename == "" || utf16Len(*meta.Filename) > MaxFilenameLength {
			return bad()
		}
		if meta.Mime != nil && utf16Len(*meta.Mime) > MaxMimeLength {
			return bad()
		}
		return meta, nil
	default:
		return bad()
	}
}

// V2EncryptReader streams a Nullbin v2 encrypted blob on demand without
// buffering the entire file in memory.
type V2EncryptReader struct {
	stream       *nbcrypto.SecretStream
	prefix       []byte
	metaHeader   []byte // 4-byte metaLen || metaJSON
	metaOff      int
	file         io.Reader
	fileRemain   int64
	padRemain    int64
	paddedTotal  int64
	plainWritten int64
	plainBuf     []byte
	outBuf       []byte
	outOff       int
	headerSent   bool
	headerBytes  [HeaderBytes]byte
	done         bool
	closed       bool
}

// NewV2EncryptReader constructs a streaming v2 blob encryptor and returns the
// exact total ciphertext blob size alongside the reader.
// The caller retains ownership of closing file (if it implements io.Closer).
// streamKey is consumed immediately and NOT retained after initialization.
func NewV2EncryptReader(streamKey, prefix []byte, meta PasteMeta, file io.Reader) (*V2EncryptReader, int64, error) {
	if len(prefix) != PrefixBytes {
		return nil, 0, newErr(CodeFormat, "invalid prefix length")
	}
	if meta.Type == "file" && file == nil && meta.Size > 0 {
		return nil, 0, newErr(CodeFormat, "missing file reader")
	}
	metaBytes, err := EncodeMeta(meta)
	if err != nil {
		return nil, 0, err
	}
	streamLen := int64(MetaLengthBytes) + int64(len(metaBytes)) + meta.Size
	if streamLen > MaxStreamLength {
		return nil, 0, newErr(CodeTooLarge, "paste exceeds maximum stream length")
	}
	paddedLen, err := PaddedLength(streamLen)
	if err != nil {
		return nil, 0, err
	}

	st, header, err := nbcrypto.InitPush(streamKey)
	if err != nil {
		return nil, 0, err
	}

	metaHeader := make([]byte, MetaLengthBytes+len(metaBytes))
	binary.BigEndian.PutUint32(metaHeader[0:4], uint32(len(metaBytes)))
	copy(metaHeader[4:], metaBytes)

	r := &V2EncryptReader{
		stream:      st,
		prefix:      append([]byte(nil), prefix...),
		metaHeader:  metaHeader,
		file:        file,
		fileRemain:  meta.Size,
		padRemain:   paddedLen - streamLen,
		paddedTotal: paddedLen,
		plainBuf:    make([]byte, ChunkSize),
	}
	copy(r.headerBytes[0:PrefixBytes], prefix)
	copy(r.headerBytes[PrefixBytes:HeaderBytes], header[:])
	clear(header[:])

	return r, BlobSize(paddedLen), nil
}

// Close zeros internal secret buffers and closes the secretstream state.
func (r *V2EncryptReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	if r.stream != nil {
		r.stream.Close()
	}
	clear(r.plainBuf)
	clear(r.metaHeader)
	clear(r.outBuf)
	return nil
}

func (r *V2EncryptReader) fillPlainChunk() (int, error) {
	fill := 0
	for fill < ChunkSize {
		// 1. Metadata length + JSON
		if r.metaOff < len(r.metaHeader) {
			n := copy(r.plainBuf[fill:], r.metaHeader[r.metaOff:])
			r.metaOff += n
			fill += n
			continue
		}
		// 2. File content (exact meta.Size bytes)
		if r.fileRemain > 0 {
			want := min(int64(ChunkSize-fill), r.fileRemain)
			n, err := io.ReadFull(r.file, r.plainBuf[fill:fill+int(want)])
			fill += n
			r.fileRemain -= int64(n)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return 0, newErr(CodeFormat, "file changed size while reading")
				}
				return 0, err
			}
			// Once all expected bytes are read, verify the file did not grow.
			if r.fileRemain == 0 {
				var extra [1]byte
				en, eerr := r.file.Read(extra[:])
				if en > 0 {
					return 0, newErr(CodeFormat, "file grew while reading")
				}
				if eerr != nil && !errors.Is(eerr, io.EOF) {
					return 0, eerr
				}
			}
			continue
		}
		// 3. Zero padding
		if r.padRemain > 0 {
			want := int(min(int64(ChunkSize-fill), r.padRemain))
			clear(r.plainBuf[fill : fill+want])
			fill += want
			r.padRemain -= int64(want)
			continue
		}
		break
	}
	return fill, nil
}

// Read implements io.Reader, streaming prefix, secretstream header, and framed ciphertext.
func (r *V2EncryptReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	if !r.headerSent {
		r.outBuf = r.headerBytes[:]
		r.outOff = 0
		r.headerSent = true
	}

	for r.outOff >= len(r.outBuf) {
		if r.done {
			return 0, io.EOF
		}
		fill, err := r.fillPlainChunk()
		if err != nil {
			_ = r.Close()
			return 0, err
		}
		if fill == 0 {
			if r.plainWritten != r.paddedTotal {
				_ = r.Close()
				return 0, newErr(CodeFormat, "padding length mismatch")
			}
			r.done = true
			return 0, io.EOF
		}
		if r.plainWritten+int64(fill) > r.paddedTotal {
			_ = r.Close()
			return 0, newErr(CodeFormat, "padding length mismatch")
		}

		var ad []byte
		if r.plainWritten == 0 {
			ad = r.prefix
		}
		isFinal := r.plainWritten+int64(fill) == r.paddedTotal
		tag := nbcrypto.TagMessage
		if isFinal {
			tag = nbcrypto.TagFinal
		}

		ct, err := r.stream.Push(r.plainBuf[:fill], ad, tag)
		clear(r.plainBuf[:fill])
		if err != nil {
			_ = r.Close()
			return 0, err
		}
		r.plainWritten += int64(fill)

		frame := make([]byte, FrameLengthBytes+len(ct))
		binary.BigEndian.PutUint32(frame[0:4], uint32(len(ct)))
		copy(frame[4:], ct)
		r.outBuf = frame
		r.outOff = 0
		if isFinal {
			r.done = true
		}
	}

	n := copy(p, r.outBuf[r.outOff:])
	r.outOff += n
	return n, nil
}

// PasswordCallback requests a password when decrypting a password-protected
// blob. attempt starts at 0 and increments after each wrong password.
// Return (nil, err) to stop prompting; returning ErrCancelled yields CodeCancelled.
type PasswordCallback func(attempt int, salt [SaltBytes]byte) ([]byte, error)

// ErrCancelled may be returned by PasswordCallback when the user cancels.
var ErrCancelled = errors.New("cancelled")

// OpenedBlob represents an authenticated paste header/metadata and optional
// streaming attachment reader.
type OpenedBlob struct {
	Prefix        Prefix
	Meta          PasteMeta
	BlobSize      int64
	CommentToken  string
	CommentKey    []byte // zeroed by Close()
	File          io.ReadCloser
	hasDiscussion bool
}

// Close zeros any retained discussion key and closes the file stream if open.
func (o *OpenedBlob) Close() error {
	if o == nil {
		return nil
	}
	clear(o.CommentKey)
	o.CommentKey = nil
	if o.File != nil {
		return o.File.Close()
	}
	return nil
}

func readExact(r io.Reader, n int) ([]byte, error) {
	if n < 0 || n > MaxMetaBytes+ABytes {
		return nil, newErr(CodeTooLarge, "malformed paste frame length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, newErr(CodeTruncated, "paste data is incomplete")
		}
		return nil, err
	}
	return buf, nil
}

func readFrame(r io.Reader, maxPlain int) ([]byte, error) {
	lenBytes, err := readExact(r, FrameLengthBytes)
	if err != nil {
		return nil, err
	}
	frameLen := binary.BigEndian.Uint32(lenBytes)
	if frameLen < ABytes || uint64(frameLen) > uint64(maxPlain)+ABytes {
		return nil, newErr(CodeFormat, "malformed paste frame length")
	}
	return readExact(r, int(frameLen))
}

func verifyEOF(r io.Reader) error {
	var extra [1]byte
	n, err := r.Read(extra[:])
	if n > 0 {
		return newErr(CodeTampered, "unexpected trailing data after end of paste")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// OpenBlob decrypts and validates a Nullbin v2 (padded) or v1 (unpadded) blob.
//
// For text pastes, the entire stream (including padding and EOF check) is
// verified before OpenBlob returns.
// For file pastes, OpenBlob returns a File reader; callers MUST read until
// io.EOF (which validates TAG_FINAL, zero-padding, and absence of trailing
// bytes) before committing the output file.
func OpenBlob(src io.Reader, fragmentKey []byte, askPassword PasswordCallback) (*OpenedBlob, error) {
	if len(fragmentKey) != KeyBytes {
		return nil, newErr(CodeWrongKey, "invalid fragment key")
	}

	prefixBytes, err := readExact(src, PrefixBytes)
	if err != nil {
		return nil, err
	}
	prefix, err := ParsePrefix(prefixBytes)
	if err != nil {
		return nil, err
	}
	header, err := readExact(src, StreamHeaderBytes)
	if err != nil {
		return nil, err
	}

	padded := prefix.Version == Version
	firstMaxPlain := ChunkSize
	if !padded {
		firstMaxPlain = MaxMetaBytes
	}
	firstCT, err := readFrame(src, firstMaxPlain)
	if err != nil {
		return nil, err
	}

	tryMaster := func(master []byte) (*nbcrypto.SecretStream, []byte, byte, bool) {
		streamKey, err := nbcrypto.DeriveStreamKey(master)
		if err != nil {
			return nil, nil, 0, false
		}
		defer clear(streamKey)

		st, err := nbcrypto.InitPull(header, streamKey)
		if err != nil {
			return nil, nil, 0, false
		}
		plain, tag, err := st.Pull(firstCT, prefixBytes)
		if err != nil {
			st.Close()
			return nil, nil, 0, false
		}
		return st, plain, tag, true
	}

	var master []byte
	var st *nbcrypto.SecretStream
	var firstPlain []byte
	var firstTag byte

	if !prefix.Password {
		master = make([]byte, KeyBytes)
		copy(master, fragmentKey)
		var ok bool
		st, firstPlain, firstTag, ok = tryMaster(master)
		if !ok {
			clear(master)
			return nil, newErr(CodeWrongKey, "paste cannot be decrypted: invalid link key or modified data")
		}
	} else {
		if askPassword == nil {
			return nil, newErr(CodeWrongPassword, "paste requires a password")
		}
		for attempt := 0; ; attempt++ {
			pw, err := askPassword(attempt, prefix.Salt)
			if err != nil {
				if errors.Is(err, ErrCancelled) {
					return nil, newErr(CodeCancelled, "cancelled")
				}
				return nil, err
			}
			if pw == nil {
				return nil, newErr(CodeCancelled, "cancelled")
			}
			candidate, derr := nbcrypto.DeriveMasterKey(fragmentKey, pw, prefix.Salt[:])
			clear(pw)
			if derr != nil {
				return nil, derr
			}
			var ok bool
			st, firstPlain, firstTag, ok = tryMaster(candidate)
			if ok {
				master = candidate
				break
			}
			clear(candidate)
		}
	}
	defer clear(master)

	if padded {
		return openPadded(src, prefix, st, firstPlain, firstTag, master)
	}
	return openUnpadded(src, prefix, st, firstPlain, firstTag, master)
}

func validV2Frame(plain []byte, tag byte) bool {
	return (tag == nbcrypto.TagMessage && len(plain) == ChunkSize) ||
		(tag == nbcrypto.TagFinal && len(plain) > 0 && len(plain) <= ChunkSize)
}

func openPadded(src io.Reader, prefix Prefix, st *nbcrypto.SecretStream, firstPlain []byte, firstTag byte, master []byte) (*OpenedBlob, error) {
	if !validV2Frame(firstPlain, firstTag) {
		st.Close()
		clear(firstPlain)
		return nil, newErr(CodeFormat, "malformed paste frame")
	}

	dec := &v2Decoder{
		src:       src,
		st:        st,
		buf:       firstPlain,
		final:     firstTag == nbcrypto.TagFinal,
		decrypted: int64(len(firstPlain)),
		expected:  MaxStreamLength,
	}

	metaLenBytes, err := dec.readExactPlain(MetaLengthBytes)
	if err != nil {
		dec.close()
		return nil, err
	}
	metaLen := binary.BigEndian.Uint32(metaLenBytes)
	if metaLen > MaxMetaBytes {
		dec.close()
		return nil, newErr(CodeFormat, "malformed paste metadata length")
	}
	metaBytes, err := dec.readExactPlain(int(metaLen))
	if err != nil {
		dec.close()
		return nil, err
	}
	meta, err := ParseMeta(metaBytes)
	clear(metaBytes)
	if err != nil {
		dec.close()
		return nil, err
	}

	contentLen := int64(MetaLengthBytes) + int64(metaLen) + meta.Size
	if contentLen > MaxStreamLength {
		dec.close()
		return nil, newErr(CodeFormat, "malformed paste length")
	}
	expected, err := PaddedLength(contentLen)
	if err != nil {
		dec.close()
		return nil, newErr(CodeFormat, "malformed paste padding length")
	}
	dec.expected = expected
	if dec.decrypted > dec.expected || (dec.final && dec.decrypted != dec.expected) {
		dec.close()
		return nil, newErr(CodeFormat, "malformed paste padding length")
	}

	opened := &OpenedBlob{
		Prefix:        prefix,
		Meta:          meta,
		BlobSize:      BlobSize(expected),
		hasDiscussion: meta.Discussion,
	}
	if meta.Discussion {
		tok, err := nbcrypto.DeriveCommentToken(master)
		if err != nil {
			dec.close()
			return nil, err
		}
		key, err := nbcrypto.DeriveCommentKey(master)
		if err != nil {
			dec.close()
			return nil, err
		}
		opened.CommentToken = tok
		opened.CommentKey = key
	}

	if meta.Type == "text" {
		if err := dec.verifyPaddingAndEOF(); err != nil {
			dec.close()
			_ = opened.Close()
			return nil, err
		}
		dec.close()
		return opened, nil
	}

	dec.fileRemain = meta.Size
	opened.File = &v2FileReader{dec: dec}
	return opened, nil
}

type v2Decoder struct {
	src        io.Reader
	st         *nbcrypto.SecretStream
	buf        []byte
	final      bool
	decrypted  int64
	expected   int64
	fileRemain int64
	finished   bool
}

func (d *v2Decoder) close() {
	if d.st != nil {
		d.st.Close()
	}
	clear(d.buf)
	d.buf = nil
}

func (d *v2Decoder) nextFrame() error {
	if d.final {
		return newErr(CodeFormat, "paste stream ended before content finished")
	}
	ct, err := readFrame(d.src, ChunkSize)
	if err != nil {
		return err
	}
	plain, tag, err := d.st.Pull(ct, nil)
	if err != nil {
		return newErr(CodeTampered, "paste was modified or corrupted")
	}
	if !validV2Frame(plain, tag) {
		clear(plain)
		return newErr(CodeFormat, "malformed paste frame")
	}
	d.decrypted += int64(len(plain))
	if d.decrypted > d.expected {
		clear(plain)
		return newErr(CodeFormat, "paste exceeds expected padded length")
	}
	d.final = tag == nbcrypto.TagFinal
	d.buf = plain
	return nil
}

func (d *v2Decoder) readExactPlain(n int) ([]byte, error) {
	out := make([]byte, n)
	for off := 0; off < n; {
		if len(d.buf) == 0 {
			if err := d.nextFrame(); err != nil {
				clear(out)
				return nil, err
			}
		}
		k := copy(out[off:], d.buf)
		clear(d.buf[:k])
		d.buf = d.buf[k:]
		off += k
	}
	return out, nil
}

func (d *v2Decoder) verifyPaddingAndEOF() error {
	for {
		for _, b := range d.buf {
			if b != 0 {
				return newErr(CodeFormat, "non-zero byte in paste padding")
			}
		}
		clear(d.buf)
		d.buf = nil
		if d.final {
			break
		}
		if err := d.nextFrame(); err != nil {
			return err
		}
	}
	if d.decrypted != d.expected {
		return newErr(CodeFormat, fmt.Sprintf("paste padded length mismatch: got %d, want %d", d.decrypted, d.expected))
	}
	if err := verifyEOF(d.src); err != nil {
		return err
	}
	d.finished = true
	return nil
}

type v2FileReader struct {
	dec    *v2Decoder
	closed bool
}

func (f *v2FileReader) Read(p []byte) (int, error) {
	if f.closed {
		return 0, io.ErrClosedPipe
	}
	if f.dec.fileRemain == 0 {
		if !f.dec.finished {
			if err := f.dec.verifyPaddingAndEOF(); err != nil {
				f.dec.close()
				return 0, err
			}
			f.dec.close()
		}
		return 0, io.EOF
	}

	if len(f.dec.buf) == 0 {
		if err := f.dec.nextFrame(); err != nil {
			f.dec.close()
			return 0, err
		}
	}
	take := int(min(int64(len(p)), min(int64(len(f.dec.buf)), f.dec.fileRemain)))
	n := copy(p[:take], f.dec.buf[:take])
	clear(f.dec.buf[:n])
	f.dec.buf = f.dec.buf[n:]
	f.dec.fileRemain -= int64(n)

	if f.dec.fileRemain == 0 {
		if err := f.dec.verifyPaddingAndEOF(); err != nil {
			f.dec.close()
			return 0, err
		}
		f.dec.close()
		return n, io.EOF
	}
	return n, nil
}

func (f *v2FileReader) Close() error {
	if f.closed {
		return nil
	}
	f.closed = true
	f.dec.close()
	return nil
}

// openUnpadded implements read-only support for legacy v1 blobs.
func openUnpadded(src io.Reader, prefix Prefix, st *nbcrypto.SecretStream, firstPlain []byte, firstTag byte, master []byte) (*OpenedBlob, error) {
	defer clear(firstPlain)
	if firstTag != nbcrypto.TagMessage && firstTag != nbcrypto.TagFinal {
		st.Close()
		return nil, newErr(CodeFormat, "malformed v1 paste frame tag")
	}
	isFinal := firstTag == nbcrypto.TagFinal
	meta, err := ParseMeta(firstPlain)
	if err != nil {
		st.Close()
		return nil, err
	}
	if (meta.Type == "text") != isFinal {
		st.Close()
		return nil, newErr(CodeFormat, "malformed v1 paste metadata")
	}

	const frameOverhead = int64(FrameLengthBytes + ABytes)
	var fileFrames int64
	if !isFinal {
		fileFrames = max(int64(1), (meta.Size+ChunkSize-1)/ChunkSize)
	}
	blobSize := int64(HeaderBytes) + frameOverhead + int64(len(firstPlain)) + fileFrames*frameOverhead + meta.Size

	opened := &OpenedBlob{
		Prefix:        prefix,
		Meta:          meta,
		BlobSize:      blobSize,
		hasDiscussion: meta.Discussion,
	}
	if meta.Discussion {
		tok, err := nbcrypto.DeriveCommentToken(master)
		if err != nil {
			st.Close()
			return nil, err
		}
		key, err := nbcrypto.DeriveCommentKey(master)
		if err != nil {
			st.Close()
			return nil, err
		}
		opened.CommentToken = tok
		opened.CommentKey = key
	}

	if isFinal {
		st.Close()
		if err := verifyEOF(src); err != nil {
			_ = opened.Close()
			return nil, err
		}
		return opened, nil
	}

	opened.File = &v1FileReader{
		src:      src,
		st:       st,
		wantSize: meta.Size,
	}
	return opened, nil
}

type v1FileReader struct {
	src      io.Reader
	st       *nbcrypto.SecretStream
	wantSize int64
	total    int64
	buf      []byte
	done     bool
	closed   bool
}

func (f *v1FileReader) Read(p []byte) (int, error) {
	if f.closed {
		return 0, io.ErrClosedPipe
	}
	for len(f.buf) == 0 {
		if f.done {
			return 0, io.EOF
		}
		ct, err := readFrame(f.src, ChunkSize)
		if err != nil {
			f.closeInternal()
			return 0, err
		}
		plain, tag, err := f.st.Pull(ct, nil)
		if err != nil {
			f.closeInternal()
			return 0, newErr(CodeTampered, "paste was modified or corrupted")
		}
		f.total += int64(len(plain))
		switch tag {
		case nbcrypto.TagMessage:
			if len(plain) != ChunkSize || f.total >= f.wantSize {
				clear(plain)
				f.closeInternal()
				return 0, newErr(CodeFormat, "malformed v1 file frame")
			}
			f.buf = plain
		case nbcrypto.TagFinal:
			if f.total != f.wantSize || (len(plain) == 0 && f.wantSize != 0) {
				clear(plain)
				f.closeInternal()
				return 0, newErr(CodeTampered, "file size does not match metadata")
			}
			if err := verifyEOF(f.src); err != nil {
				clear(plain)
				f.closeInternal()
				return 0, err
			}
			f.done = true
			f.buf = plain
			f.st.Close()
			if len(f.buf) == 0 {
				return 0, io.EOF
			}
		default:
			clear(plain)
			f.closeInternal()
			return 0, newErr(CodeFormat, "malformed v1 file frame tag")
		}
	}

	n := copy(p, f.buf)
	clear(f.buf[:n])
	f.buf = f.buf[n:]
	if len(f.buf) == 0 && f.done {
		return n, io.EOF
	}
	return n, nil
}

func (f *v1FileReader) closeInternal() {
	if f.st != nil {
		f.st.Close()
	}
	clear(f.buf)
	f.buf = nil
}

func (f *v1FileReader) Close() error {
	if f.closed {
		return nil
	}
	f.closed = true
	f.closeInternal()
	return nil
}
