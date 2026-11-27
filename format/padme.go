// Package format implements Nullbin's blob v2 (padded) and v1 (unpadded,
// read-only) framing, Padmé size padding, strict metadata validation, and
// deterministic stored ZIP archive creation for multi-file pastes.
package format

import (
	"errors"
	"math/bits"
)

const (
	// Version is the blob format version written for new pastes.
	Version byte = 2
	// VersionUnpadded is the legacy v1 blob format version accepted on read.
	VersionUnpadded byte = 1

	FlagPassword byte = 0x01
	KnownFlags   byte = FlagPassword

	KeyBytes          = 32
	SaltBytes         = 16
	PrefixBytes       = 4 + 1 + 1 + SaltBytes // 22
	StreamHeaderBytes = 24
	HeaderBytes       = PrefixBytes + StreamHeaderBytes // 46
	FrameLengthBytes  = 4
	ABytes            = 17

	// ChunkSize is the exact plaintext size of every non-final frame.
	ChunkSize = 64 * 1024
	// MaxMetaBytes is the largest encrypted metadata JSON accepted.
	MaxMetaBytes = 16 * 1024 * 1024
	// MaxFilenameLength is the maximum UTF-16 code-unit length of a metadata filename.
	MaxFilenameLength = 255
	// MaxMimeLength is the maximum UTF-16 code-unit length of a metadata MIME type.
	MaxMimeLength = 255

	MetaLengthBytes = 4
	// MinPaddedLength is the 16 KiB minimum padded stream size for v2 blobs.
	MinPaddedLength int64 = 16 * 1024
	// MaxStreamLength keeps all arithmetic exact and matches the JS implementation (2^48).
	MaxStreamLength int64 = 1 << 48
)

// Magic is the 4-byte Nullbin blob prefix magic ("NBN1").
var Magic = [4]byte{'N', 'B', 'N', '1'}

var ErrBadStreamLength = errors.New("format: stream length out of bounds")

// PaddedLength computes the Nullbin v2 padded length of an n-byte plaintext
// stream: at least MinPaddedLength (16 KiB), and above that Padmé rounding
// (Nikitin et al., 2019).
func PaddedLength(n int64) (int64, error) {
	return PaddedLengthWithMin(n, MinPaddedLength)
}

// PaddedLengthWithMin computes Padmé padding with an explicit power-of-two minimum.
func PaddedLengthWithMin(n, minimum int64) (int64, error) {
	if n < 0 || n > MaxStreamLength || minimum <= 0 {
		return 0, ErrBadStreamLength
	}
	if n <= minimum {
		return minimum, nil
	}
	e := bits.Len64(uint64(n)) - 1 // floor(log2(n))
	s := bits.Len64(uint64(e))     // floor(log2(e)) + 1
	step := int64(1) << (e - s)
	mask := step - 1
	return (n + mask) &^ mask, nil
}

// FrameCount returns the number of 64 KiB secretstream frames needed to carry
// a v2 stream of streamLength bytes.
func FrameCount(streamLength int64) int64 {
	if streamLength <= 0 {
		return 0
	}
	return (streamLength + ChunkSize - 1) / ChunkSize
}

// BlobSize returns the exact byte length of a v2 encrypted blob whose padded
// plaintext stream is paddedStreamLength bytes.
func BlobSize(paddedStreamLength int64) int64 {
	return HeaderBytes + FrameCount(paddedStreamLength)*(FrameLengthBytes+ABytes) + paddedStreamLength
}
