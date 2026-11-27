package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/blake2b"
)

func TestPoly1305RFC8439(t *testing.T) {
	// RFC 8439 Section 2.5.2 test vector.
	keyBytes, err := hex.DecodeString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], keyBytes)

	msg := []byte("Cryptographic Forum Research Group")
	want, err := hex.DecodeString("a8061dc1305136c6c22b8baf0c0127a9")
	if err != nil {
		t.Fatal(err)
	}

	var p poly1305State
	p.init(&key)
	p.write(msg[:5])
	p.write(msg[5:19])
	p.write(msg[19:])
	var got [16]byte
	p.sum(&got)

	if !bytes.Equal(got[:], want) {
		t.Fatalf("poly1305 mismatch:\ngot:  %x\nwant: %x", got, want)
	}
}

func TestBLAKE2bMatchesXCrypto(t *testing.T) {
	cases := []struct {
		key []byte
		msg []byte
	}{
		{nil, nil},
		{nil, []byte("abc")},
		{[]byte("0123456789abcdef0123456789abcdef"), nil},
		{[]byte("0123456789abcdef0123456789abcdef"), []byte("hello world")},
		{[]byte("0123456789abcdef0123456789abcdef"), bytes.Repeat([]byte("A"), 300)},
	}
	for i, tc := range cases {
		got, err := blake2b256SaltPersonal(tc.key, tc.msg, nil, nil)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		h, err := blake2b.New256(tc.key)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		_, _ = h.Write(tc.msg)
		want := h.Sum(nil)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("case %d mismatch:\ngot:  %x\nwant: %x", i, got, want)
		}
	}
}

func TestSecretStreamRoundTripAndRekey(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, SecretStreamKeyBytes)
	push, header, err := InitPush(key)
	if err != nil {
		t.Fatalf("InitPush: %v", err)
	}
	defer push.Close()

	pull, err := InitPull(header[:], key)
	if err != nil {
		t.Fatalf("InitPull: %v", err)
	}
	defer pull.Close()

	frames := []struct {
		msg []byte
		ad  []byte
		tag byte
	}{
		{[]byte("first frame with prefix AAD"), []byte("NBN1\x02\x000123456789abcdef"), TagMessage},
		{bytes.Repeat([]byte{0xAB}, 65536), nil, TagMessage},
		{[]byte("explicit rekey frame"), []byte("rekey-ad"), TagRekey},
		{[]byte("post-rekey frame"), nil, TagMessage},
		{[]byte("final frame"), nil, TagFinal},
	}

	for i, f := range frames {
		ct, err := push.Push(f.msg, f.ad, f.tag)
		if err != nil {
			t.Fatalf("frame %d Push: %v", i, err)
		}
		plain, tag, err := pull.Pull(ct, f.ad)
		if err != nil {
			t.Fatalf("frame %d Pull: %v", i, err)
		}
		if tag != f.tag {
			t.Fatalf("frame %d tag = %d, want %d", i, tag, f.tag)
		}
		if !bytes.Equal(plain, f.msg) {
			t.Fatalf("frame %d plaintext mismatch", i)
		}
	}

	// Pushing or pulling after TagFinal must fail.
	if _, err := push.Push([]byte("extra"), nil, TagMessage); err != ErrStreamFinalized {
		t.Fatalf("post-final Push err = %v, want ErrStreamFinalized", err)
	}
	if _, _, err := pull.Pull(make([]byte, SecretStreamABytes), nil); err != ErrStreamFinalized {
		t.Fatalf("post-final Pull err = %v, want ErrStreamFinalized", err)
	}
}

func TestSecretStreamCounterWrapRekeys(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, SecretStreamKeyBytes)
	push, header, err := InitPush(key)
	if err != nil {
		t.Fatal(err)
	}
	defer push.Close()
	pull, err := InitPull(header[:], key)
	if err != nil {
		t.Fatal(err)
	}
	defer pull.Close()

	// Set counter to max uint32 so the next frame triggers automatic counter wrap rekey.
	binary.LittleEndian.PutUint32(push.nonce[0:4], 0xffffffff)
	binary.LittleEndian.PutUint32(pull.nonce[0:4], 0xffffffff)

	ct1, err := push.Push([]byte("wrap"), nil, TagMessage)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(push.nonce[0:4]); got != 1 {
		t.Fatalf("expected counter reset to 1 after wrap, got %d", got)
	}
	p1, _, err := pull.Pull(ct1, nil)
	if err != nil || string(p1) != "wrap" {
		t.Fatalf("pull wrap frame failed: %v %q", err, p1)
	}

	ct2, err := push.Push([]byte("after-wrap"), nil, TagFinal)
	if err != nil {
		t.Fatal(err)
	}
	p2, tag, err := pull.Pull(ct2, nil)
	if err != nil || tag != TagFinal || string(p2) != "after-wrap" {
		t.Fatalf("pull after-wrap failed: %v tag=%d %q", err, tag, p2)
	}
}

func TestSecretStreamTamperDetection(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, SecretStreamKeyBytes)
	push, header, err := InitPush(key)
	if err != nil {
		t.Fatal(err)
	}
	defer push.Close()

	ad := []byte("prefix")
	ct, err := push.Push([]byte("secret payload"), ad, TagFinal)
	if err != nil {
		t.Fatal(err)
	}

	// Flip each part: tag byte, payload byte, MAC byte, and wrong AAD.
	for _, idx := range []int{0, 5, len(ct) - 1} {
		tampered := append([]byte(nil), ct...)
		tampered[idx] ^= 0x01
		pull, err := InitPull(header[:], key)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := pull.Pull(tampered, ad); err != ErrInvalidCiphertext {
			t.Fatalf("byte %d flip: got err=%v, want ErrInvalidCiphertext", idx, err)
		}
		pull.Close()
	}

	pull, err := InitPull(header[:], key)
	if err != nil {
		t.Fatal(err)
	}
	defer pull.Close()
	if _, _, err := pull.Pull(ct, []byte("wrong-prefix")); err != ErrInvalidCiphertext {
		t.Fatalf("wrong AAD: got err=%v, want ErrInvalidCiphertext", err)
	}
}

func TestPasswordNFCAndGenerate(t *testing.T) {
	frag := bytes.Repeat([]byte{0x33}, KeyBytes)
	salt := bytes.Repeat([]byte{0x44}, SaltBytes)

	// "café1234" in NFC vs NFD must produce the exact same master key.
	nfc := []byte("caf\u00e91234")
	nfd := []byte("cafe\u03011234")
	k1, err := DeriveMasterKey(frag, nfc, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(k1)
	k2, err := DeriveMasterKey(frag, nfd, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(k2)
	if !bytes.Equal(k1, k2) {
		t.Fatal("NFC and NFD passwords produced different master keys")
	}

	pw, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(pw)
	if len(pw) != GeneratedPasswordLength {
		t.Fatalf("generated password length = %d, want %d", len(pw), GeneratedPasswordLength)
	}
	if err := ValidateNewPassword(pw); err != nil {
		t.Fatalf("generated password failed validation: %v", err)
	}
	if err := ValidateNewPassword([]byte("1234567")); err != ErrPasswordTooShort {
		t.Fatalf("short password err = %v, want ErrPasswordTooShort", err)
	}
}
