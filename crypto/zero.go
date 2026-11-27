// Package crypto implements Nullbin's libsodium-compatible client-side
// cryptography: Argon2id + NFC master key derivation, BLAKE2b-256 KDF
// subkeys, recipient access tokens, and XChaCha20-Poly1305 secretstream.
package crypto

// Zero overwrites b with zero bytes to limit key material lifetime in memory.
func Zero(b []byte) {
	clear(b)
}
