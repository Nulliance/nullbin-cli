package crypto

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// RFC 7693 BLAKE2b-256 with parameter-block salt and personalization support.
// Used for libsodium's crypto_kdf_derive_from_key (which sets a 16-byte salt
// and 16-byte personalization block, parameters not exposed by x/crypto/blake2b).

var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

var blake2bSigma = [12][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

func blake2bG(v *[16]uint64, a, b, c, d int, x, y uint64) {
	v[a] = v[a] + v[b] + x
	v[d] = bits.RotateLeft64(v[d]^v[a], -32)
	v[c] = v[c] + v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -24)
	v[a] = v[a] + v[b] + y
	v[d] = bits.RotateLeft64(v[d]^v[a], -16)
	v[c] = v[c] + v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -63)
}

func blake2bCompress(h *[8]uint64, block *[128]byte, t0, t1 uint64, final bool) {
	var m [16]uint64
	for i := range 16 {
		m[i] = binary.LittleEndian.Uint64(block[i*8 : i*8+8])
	}

	var v [16]uint64
	copy(v[0:8], h[:])
	copy(v[8:16], blake2bIV[:])
	v[12] ^= t0
	v[13] ^= t1
	if final {
		v[14] = ^v[14]
	}

	for r := range 12 {
		s := &blake2bSigma[r]
		blake2bG(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		blake2bG(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		blake2bG(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		blake2bG(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		blake2bG(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		blake2bG(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		blake2bG(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		blake2bG(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}

	for i := range 8 {
		h[i] ^= v[i] ^ v[i+8]
	}

	clear(m[:])
	clear(v[:])
}

// blake2b256SaltPersonal computes BLAKE2b-256 with optional key (0..64 bytes),
// optional 16-byte salt, optional 16-byte personalization, and message msg.
func blake2b256SaltPersonal(key, msg, salt, personal []byte) ([32]byte, error) {
	var out [32]byte
	if len(key) > 64 {
		return out, errors.New("blake2b: key too long")
	}
	if len(salt) != 0 && len(salt) != 16 {
		return out, errors.New("blake2b: salt must be 0 or 16 bytes")
	}
	if len(personal) != 0 && len(personal) != 16 {
		return out, errors.New("blake2b: personalization must be 0 or 16 bytes")
	}

	var param [64]byte
	param[0] = 32 // digest length
	param[1] = byte(len(key))
	param[2] = 1 // fanout
	param[3] = 1 // depth
	if len(salt) == 16 {
		copy(param[32:48], salt)
	}
	if len(personal) == 16 {
		copy(param[48:64], personal)
	}

	var h [8]uint64
	for i := range 8 {
		h[i] = blake2bIV[i] ^ binary.LittleEndian.Uint64(param[i*8:i*8+8])
	}
	clear(param[:])

	var block [128]byte
	var t0, t1 uint64
	addCounter := func(n uint64) {
		prev := t0
		t0 += n
		if t0 < prev {
			t1++
		}
	}

	bufLen := 0
	if len(key) > 0 {
		copy(block[:], key)
		bufLen = 128
	}

	for len(msg) > 0 {
		if bufLen == 128 {
			addCounter(128)
			blake2bCompress(&h, &block, t0, t1, false)
			clear(block[:])
			bufLen = 0
		}
		n := copy(block[bufLen:], msg)
		bufLen += n
		msg = msg[n:]
	}

	addCounter(uint64(bufLen))
	clear(block[bufLen:])
	blake2bCompress(&h, &block, t0, t1, true)
	clear(block[:])

	for i := range 4 {
		binary.LittleEndian.PutUint64(out[i*8:i*8+8], h[i])
	}
	clear(h[:])
	return out, nil
}
