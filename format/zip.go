package format

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

const (
	// MaxFiles is the maximum number of files packed into a single paste archive.
	MaxFiles = 100

	dosDate19800101  uint16 = (0 << 9) | (1 << 5) | 1
	zipUTF8Flag      uint16 = 0x0800
	zipMadeByUnix    uint16 = (3 << 8) | 20
	zipRegularFileRW uint32 = 0o100644 << 16
)

// Matches Windows reserved device names, alone or followed by whitespace/extension.
var windowsDeviceRe = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$|clock\$)([\s.].*)?$`)

// isDefaultIgnorable returns true for Unicode Default_Ignorable_Code_Point runes
// as well as control/format/line/paragraph separators and invisible fillers.
func isUnsafeFilenameRune(r rune) bool {
	switch r {
	case '/', '\\', ':', '*', '?', '"', '<', '>', '|',
		0x034F,                         // combining grapheme joiner
		0x061C,                         // arabic letter mark
		0x115F, 0x1160, 0x3164, 0xFFA0, // Hangul fillers
		0x17B4, 0x17B5, // Khmer inherent vowels
		0x180B, 0x180C, 0x180D, 0x180E, 0x180F, // Mongolian variation selectors
		0x2800, // Braille pattern blank
		0xFEFF: // BOM / ZWNBSP
		return true
	}
	if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cc, r) ||
		unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) ||
		unicode.Is(unicode.Cs, r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) {
		return true
	}
	return false
}

// CleanFileName sanitizes an untrusted filename to match web/src/zip.ts:
// NFC normalized, no path separators/drive letters/control/bidi/ignorable runes,
// no leading dots/whitespace, max 200 runes, no trailing dots/whitespace, and
// Windows reserved device names prefixed with '_'.
func CleanFileName(name, fallback string) string {
	nfc := norm.NFC.String(name)
	var b strings.Builder
	b.Grow(len(nfc))
	for _, r := range nfc {
		if isUnsafeFilenameRune(r) {
			b.WriteByte('_')
		} else {
			b.WriteRune(r)
		}
	}
	cleaned := strings.TrimLeftFunc(b.String(), func(r rune) bool {
		return r == '.' || unicode.IsSpace(r)
	})

	runes := []rune(cleaned)
	if len(runes) > 200 {
		runes = runes[:200]
	}
	cleaned = strings.TrimRightFunc(string(runes), func(r rune) bool {
		return r == '.' || unicode.IsSpace(r)
	})

	if windowsDeviceRe.MatchString(cleaned) {
		cleaned = "_" + cleaned
	}
	if cleaned == "" {
		return fallback
	}
	return cleaned
}

// ZipEntryName sanitizes a filename for inclusion inside a multi-file archive.
func ZipEntryName(name string) string {
	return CleanFileName(name, "file")
}

// UniqueNames deduplicates filenames case-insensitively (in NFC), matching
// web/src/zip.ts ("name (2).ext" or "name (2)").
func UniqueNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, len(names))
	for idx, name := range names {
		candidate := name
		for i := 2; ; i++ {
			key := strings.ToLower(norm.NFC.String(candidate))
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				out[idx] = candidate
				break
			}
			dot := strings.LastIndexByte(name, '.')
			if dot > 0 {
				candidate = fmt.Sprintf("%s (%d)%s", name[:dot], i, name[dot:])
			} else {
				candidate = fmt.Sprintf("%s (%d)", name, i)
			}
		}
	}
	return out
}

// ArchiveName returns the canonical Nullbin multi-file archive name.
func ArchiveName(count int) string {
	return fmt.Sprintf("%d files.zip", count)
}

// ZipInput describes one source file to include in a deterministic stored ZIP.
type ZipInput struct {
	Name string
	Size int64
	Open func() (io.ReadCloser, error)
}

type zipEntryMeta struct {
	input      ZipInput
	nameBytes  []byte
	crc        uint32
	size       uint32
	localHdr   []byte
	centralHdr []byte
}

// StoredZip is a streaming, deterministic, uncompressed ZIP archive matching
// Nullbin's web/src/zip.ts byte-for-byte.
type StoredZip struct {
	entries   []zipEntryMeta
	central   []byte
	eocd      [22]byte
	totalSize int64
}

// NewStoredZip computes CRCs and ZIP headers for 2..MaxFiles input files
// without copying file payloads into memory.
func NewStoredZip(files []ZipInput) (*StoredZip, error) {
	if len(files) < 2 || len(files) > MaxFiles {
		return nil, newErr(CodeTooLarge, fmt.Sprintf("attach from 2 to %d files", MaxFiles))
	}

	rawNames := make([]string, len(files))
	for i, f := range files {
		rawNames[i] = ZipEntryName(f.Name)
	}
	names := UniqueNames(rawNames)

	entries := make([]zipEntryMeta, len(files))
	var offset uint64
	var centralBuf bytes.Buffer
	copyBuf := make([]byte, 256*1024)

	for i, f := range files {
		if f.Size < 0 || uint64(f.Size) > math.MaxUint32 || offset > math.MaxUint32 {
			return nil, newErr(CodeTooLarge, "files are too large for standard zip")
		}
		if f.Open == nil {
			return nil, newErr(CodeFormat, "missing file opener")
		}

		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		h := crc32.NewIEEE()
		n, copyErr := io.CopyBuffer(h, rc, copyBuf)
		closeErr := rc.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if n != f.Size {
			return nil, newErr(CodeFormat, fmt.Sprintf("%s changed while reading", names[i]))
		}

		nameBytes := []byte(names[i])
		if len(nameBytes) > math.MaxUint16 {
			return nil, newErr(CodeFormat, "archive entry name too long")
		}
		crcVal := h.Sum32()
		sz32 := uint32(f.Size)
		off32 := uint32(offset)

		local := make([]byte, 30+len(nameBytes))
		binary.LittleEndian.PutUint32(local[0:4], 0x04034b50)
		binary.LittleEndian.PutUint16(local[4:6], 10)
		binary.LittleEndian.PutUint16(local[6:8], zipUTF8Flag)
		binary.LittleEndian.PutUint16(local[8:10], 0) // stored
		binary.LittleEndian.PutUint16(local[10:12], 0)
		binary.LittleEndian.PutUint16(local[12:14], dosDate19800101)
		binary.LittleEndian.PutUint32(local[14:18], crcVal)
		binary.LittleEndian.PutUint32(local[18:22], sz32)
		binary.LittleEndian.PutUint32(local[22:26], sz32)
		binary.LittleEndian.PutUint16(local[26:28], uint16(len(nameBytes)))
		binary.LittleEndian.PutUint16(local[28:30], 0)
		copy(local[30:], nameBytes)

		central := make([]byte, 46+len(nameBytes))
		binary.LittleEndian.PutUint32(central[0:4], 0x02014b50)
		binary.LittleEndian.PutUint16(central[4:6], zipMadeByUnix)
		binary.LittleEndian.PutUint16(central[6:8], 10)
		binary.LittleEndian.PutUint16(central[8:10], zipUTF8Flag)
		binary.LittleEndian.PutUint16(central[10:12], 0)
		binary.LittleEndian.PutUint16(central[12:14], 0)
		binary.LittleEndian.PutUint16(central[14:16], dosDate19800101)
		binary.LittleEndian.PutUint32(central[16:20], crcVal)
		binary.LittleEndian.PutUint32(central[20:24], sz32)
		binary.LittleEndian.PutUint32(central[24:28], sz32)
		binary.LittleEndian.PutUint16(central[28:30], uint16(len(nameBytes)))
		binary.LittleEndian.PutUint16(central[30:32], 0)
		binary.LittleEndian.PutUint16(central[32:34], 0)
		binary.LittleEndian.PutUint16(central[34:36], 0)
		binary.LittleEndian.PutUint16(central[36:38], 0)
		binary.LittleEndian.PutUint32(central[38:42], zipRegularFileRW)
		binary.LittleEndian.PutUint32(central[42:46], off32)
		copy(central[46:], nameBytes)

		entries[i] = zipEntryMeta{
			input:      f,
			nameBytes:  nameBytes,
			crc:        crcVal,
			size:       sz32,
			localHdr:   local,
			centralHdr: central,
		}
		centralBuf.Write(central)
		offset += uint64(len(local)) + uint64(f.Size)
	}

	centralBytes := centralBuf.Bytes()
	centralSize := uint64(len(centralBytes))
	if offset > math.MaxUint32 || offset+centralSize > math.MaxUint32 {
		return nil, newErr(CodeTooLarge, "files are too large for standard zip")
	}

	z := &StoredZip{
		entries:   entries,
		central:   centralBytes,
		totalSize: int64(offset + centralSize + 22),
	}
	binary.LittleEndian.PutUint32(z.eocd[0:4], 0x06054b50)
	binary.LittleEndian.PutUint16(z.eocd[4:6], 0)
	binary.LittleEndian.PutUint16(z.eocd[6:8], 0)
	binary.LittleEndian.PutUint16(z.eocd[8:10], uint16(len(files)))
	binary.LittleEndian.PutUint16(z.eocd[10:12], uint16(len(files)))
	binary.LittleEndian.PutUint32(z.eocd[12:16], uint32(centralSize))
	binary.LittleEndian.PutUint32(z.eocd[16:20], uint32(offset))
	binary.LittleEndian.PutUint16(z.eocd[20:22], 0)

	return z, nil
}

// Size returns the exact byte length of the ZIP archive.
func (z *StoredZip) Size() int64 {
	return z.totalSize
}

// Open returns a streaming reader over the entire ZIP archive.
func (z *StoredZip) Open() io.ReadCloser {
	return &storedZipReader{z: z}
}

type storedZipReader struct {
	z        *StoredZip
	entryIdx int
	stage    int // 0=localHdr, 1=fileBody, 2=central, 3=eocd, 4=eof
	bufOff   int
	curFile  io.ReadCloser
	fileRead int64
	closed   bool
}

func (r *storedZipReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	for {
		switch r.stage {
		case 0:
			if r.entryIdx >= len(r.z.entries) {
				r.stage = 2
				r.bufOff = 0
				continue
			}
			hdr := r.z.entries[r.entryIdx].localHdr
			if r.bufOff < len(hdr) {
				n := copy(p, hdr[r.bufOff:])
				r.bufOff += n
				return n, nil
			}
			rc, err := r.z.entries[r.entryIdx].input.Open()
			if err != nil {
				return 0, err
			}
			r.curFile = rc
			r.fileRead = 0
			r.stage = 1
		case 1:
			want := int64(r.z.entries[r.entryIdx].size)
			if r.fileRead == want {
				var extra [1]byte
				en, eerr := r.curFile.Read(extra[:])
				_ = r.curFile.Close()
				r.curFile = nil
				if en > 0 {
					return 0, newErr(CodeFormat, "file grew while archiving")
				}
				if eerr != nil && !errors.Is(eerr, io.EOF) {
					return 0, eerr
				}
				r.entryIdx++
				r.bufOff = 0
				r.stage = 0
				continue
			}
			limit := min(int64(len(p)), want-r.fileRead)
			n, err := r.curFile.Read(p[:limit])
			r.fileRead += int64(n)
			if err != nil {
				if errors.Is(err, io.EOF) {
					_ = r.curFile.Close()
					r.curFile = nil
					if r.fileRead != want {
						return 0, newErr(CodeFormat, "file shrank while archiving")
					}
					r.entryIdx++
					r.bufOff = 0
					r.stage = 0
					if n > 0 {
						return n, nil
					}
					continue
				}
				_ = r.curFile.Close()
				r.curFile = nil
				return n, err
			}
			if n > 0 {
				return n, nil
			}
		case 2:
			if r.bufOff < len(r.z.central) {
				n := copy(p, r.z.central[r.bufOff:])
				r.bufOff += n
				return n, nil
			}
			r.stage = 3
			r.bufOff = 0
		case 3:
			if r.bufOff < len(r.z.eocd) {
				n := copy(p, r.z.eocd[r.bufOff:])
				r.bufOff += n
				return n, nil
			}
			r.stage = 4
			return 0, io.EOF
		default:
			return 0, io.EOF
		}
	}
}

func (r *storedZipReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	if r.curFile != nil {
		err := r.curFile.Close()
		r.curFile = nil
		return err
	}
	return nil
}
