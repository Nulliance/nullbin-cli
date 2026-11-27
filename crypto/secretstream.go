package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
)

const (
	// SecretStreamKeyBytes is the 32-byte key size for XChaCha20-Poly1305 secretstream.
	SecretStreamKeyBytes = 32
	// SecretStreamHeaderBytes is the 24-byte header size (16-byte HChaCha20 nonce + 8-byte INONCE).
	SecretStreamHeaderBytes = 24
	// SecretStreamABytes is the per-frame overhead: 1 tag byte + 16 Poly1305 MAC bytes.
	SecretStreamABytes = 17

	// Secretstream frame tags matching libsodium.
	TagMessage byte = 0x00
	TagPush    byte = 0x01
	TagRekey   byte = 0x02
	TagFinal   byte = TagPush | TagRekey // 0x03

	// MaxSecretStreamMessageBytes matches libsodium's per-message upper bound.
	// In practice Nullbin frames are at most 64 KiB (or 16 MiB for legacy v1 metadata).
	MaxSecretStreamMessageBytes = 1<<32 - 1 - SecretStreamABytes
)

var (
	ErrInvalidKey        = errors.New("crypto: invalid key length")
	ErrInvalidHeader     = errors.New("crypto: invalid secretstream header length")
	ErrStreamFinalized   = errors.New("crypto: secretstream already finalized")
	ErrInvalidCiphertext = errors.New("crypto: invalid or unauthenticated ciphertext")
	ErrMessageTooLarge   = errors.New("crypto: message too large")
)

// SecretStream implements libsodium's crypto_secretstream_xchacha20poly1305
// state machine (push and pull).
type SecretStream struct {
	k         [32]byte
	nonce     [12]byte // nonce[0:4] = uint32LE counter, nonce[4:12] = 8-byte INONCE
	finalized bool
}

// InitPush initializes a new secretstream encryption state with a random
// 24-byte header and returns both the state and header.
func InitPush(key []byte) (*SecretStream, [SecretStreamHeaderBytes]byte, error) {
	var header [SecretStreamHeaderBytes]byte
	if len(key) != SecretStreamKeyBytes {
		return nil, header, ErrInvalidKey
	}
	if _, err := rand.Read(header[:]); err != nil {
		return nil, header, err
	}
	st, err := initSecretStream(header[:], key)
	if err != nil {
		clear(header[:])
		return nil, header, err
	}
	return st, header, nil
}

// InitPull initializes a secretstream decryption state from a 24-byte header
// and 32-byte key.
func InitPull(header, key []byte) (*SecretStream, error) {
	return initSecretStream(header, key)
}

func initSecretStream(header, key []byte) (*SecretStream, error) {
	if len(key) != SecretStreamKeyBytes {
		return nil, ErrInvalidKey
	}
	if len(header) != SecretStreamHeaderBytes {
		return nil, ErrInvalidHeader
	}
	subkey, err := chacha20.HChaCha20(key, header[0:16])
	if err != nil {
		return nil, err
	}
	st := &SecretStream{}
	copy(st.k[:], subkey)
	clear(subkey)
	binary.LittleEndian.PutUint32(st.nonce[0:4], 1)
	copy(st.nonce[4:12], header[16:24])
	return st, nil
}

// Close zeros all secret state inside the stream.
func (st *SecretStream) Close() {
	if st == nil {
		return
	}
	clear(st.k[:])
	clear(st.nonce[:])
	st.finalized = true
}

// Rekey explicitly ratchets the secretstream key and INONCE, matching
// libsodium's crypto_secretstream_xchacha20poly1305_rekey.
func (st *SecretStream) Rekey() error {
	if st.finalized {
		return ErrStreamFinalized
	}
	return st.rekey()
}

func (st *SecretStream) rekey() error {
	var newKeyAndInonce [40]byte
	copy(newKeyAndInonce[0:32], st.k[:])
	copy(newKeyAndInonce[32:40], st.nonce[4:12])

	cipher, err := chacha20.NewUnauthenticatedCipher(st.k[:], st.nonce[:])
	if err != nil {
		clear(newKeyAndInonce[:])
		return err
	}
	cipher.XORKeyStream(newKeyAndInonce[:], newKeyAndInonce[:])

	copy(st.k[:], newKeyAndInonce[0:32])
	copy(st.nonce[4:12], newKeyAndInonce[32:40])
	clear(newKeyAndInonce[:])
	binary.LittleEndian.PutUint32(st.nonce[0:4], 1)
	return nil
}

func (st *SecretStream) advanceState(mac *[16]byte, tag byte) error {
	for i := range 8 {
		st.nonce[4+i] ^= mac[i]
	}
	counter := binary.LittleEndian.Uint32(st.nonce[0:4]) + 1
	binary.LittleEndian.PutUint32(st.nonce[0:4], counter)

	if tag == TagFinal {
		st.Close()
		return nil
	}
	if (tag&TagRekey) != 0 || counter == 0 {
		return st.rekey()
	}
	return nil
}

// Push encrypts and authenticates a single frame with optional additional data
// ad and libsodium tag (TagMessage, TagPush, TagRekey, TagFinal).
func (st *SecretStream) Push(m, ad []byte, tag byte) ([]byte, error) {
	if st.finalized {
		return nil, ErrStreamFinalized
	}
	if uint64(len(m)) > MaxSecretStreamMessageBytes {
		return nil, ErrMessageTooLarge
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(st.k[:], st.nonce[:])
	if err != nil {
		return nil, err
	}

	var block [64]byte
	defer clear(block[:])

	// Block 0: first 32 bytes are the Poly1305 one-time key.
	cipher.XORKeyStream(block[:], block[:])
	var otk [32]byte
	copy(otk[:], block[:32])
	var poly poly1305State
	poly.init(&otk)
	clear(otk[:])
	defer poly.clear()

	if len(ad) > 0 {
		poly.write(ad)
		poly.pad16()
	}

	// Block 1: [tag, 0, 0, ..., 0] encrypted; byte 0 is emitted, all 64 bytes are MAC'd.
	clear(block[:])
	block[0] = tag
	cipher.XORKeyStream(block[:], block[:])

	out := make([]byte, len(m)+SecretStreamABytes)
	out[0] = block[0]
	poly.write(block[:])

	// Block 2+: payload ciphertext.
	ctPayload := out[1 : 1+len(m)]
	if len(m) > 0 {
		cipher.XORKeyStream(ctPayload, m)
		poly.write(ctPayload)
	}
	// Exact libsodium padding quirk: (0x10 - 64 + mlen) & 0xf == mlen & 0xf.
	var padZeros [16]byte
	if padLen := len(m) & 0xf; padLen > 0 {
		poly.write(padZeros[:padLen])
	}

	// Length footer: uint64LE(len(ad)) || uint64LE(64 + len(m)).
	var slen [16]byte
	binary.LittleEndian.PutUint64(slen[0:8], uint64(len(ad)))
	binary.LittleEndian.PutUint64(slen[8:16], uint64(64)+uint64(len(m)))
	poly.write(slen[:])

	var mac [16]byte
	poly.sum(&mac)
	copy(out[1+len(m):], mac[:])

	if err := st.advanceState(&mac, tag); err != nil {
		clear(out)
		return nil, err
	}
	return out, nil
}

// Pull authenticates and decrypts a single frame, returning plaintext and tag.
// The Poly1305 MAC is verified in constant time before decrypting any payload
// bytes so unauthenticated plaintext is never released.
func (st *SecretStream) Pull(ct, ad []byte) ([]byte, byte, error) {
	if st.finalized {
		return nil, 0, ErrStreamFinalized
	}
	if len(ct) < SecretStreamABytes {
		return nil, 0, ErrInvalidCiphertext
	}

	mlen := len(ct) - SecretStreamABytes
	ctPayload := ct[1 : 1+mlen]
	storedMAC := ct[1+mlen:]

	cipher, err := chacha20.NewUnauthenticatedCipher(st.k[:], st.nonce[:])
	if err != nil {
		return nil, 0, err
	}

	var block [64]byte
	defer clear(block[:])

	// Block 0: Poly1305 one-time key.
	cipher.XORKeyStream(block[:], block[:])
	var otk [32]byte
	copy(otk[:], block[:32])
	var poly poly1305State
	poly.init(&otk)
	clear(otk[:])
	defer poly.clear()

	if len(ad) > 0 {
		poly.write(ad)
		poly.pad16()
	}

	// Block 1: recover tag from ct[0] ^ ks1[0], reconstruct encrypted tag block
	// for Poly1305 authentication.
	clear(block[:])
	cipher.XORKeyStream(block[:], block[:])
	tag := ct[0] ^ block[0]
	block[0] = ct[0]
	poly.write(block[:])

	if mlen > 0 {
		poly.write(ctPayload)
	}
	// Exact libsodium padding quirk: (0x10 - 64 + mlen) & 0xf == mlen & 0xf.
	var padZeros [16]byte
	if padLen := mlen & 0xf; padLen > 0 {
		poly.write(padZeros[:padLen])
	}

	var slen [16]byte
	binary.LittleEndian.PutUint64(slen[0:8], uint64(len(ad)))
	binary.LittleEndian.PutUint64(slen[8:16], uint64(64)+uint64(mlen))
	poly.write(slen[:])

	var mac [16]byte
	poly.sum(&mac)
	if subtle.ConstantTimeCompare(mac[:], storedMAC) != 1 {
		clear(mac[:])
		return nil, 0, ErrInvalidCiphertext
	}

	// MAC verified: now decrypt payload using block counter 2+.
	plain := make([]byte, mlen)
	if mlen > 0 {
		cipher.XORKeyStream(plain, ctPayload)
	}

	if err := st.advanceState(&mac, tag); err != nil {
		clear(plain)
		clear(mac[:])
		return nil, 0, err
	}
	clear(mac[:])
	return plain, tag, nil
}
