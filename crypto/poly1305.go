package crypto

import (
	"encoding/binary"
	"math/bits"
)

// Constant-time RFC 8439 Poly1305 authenticator using 64-bit limbs.
type poly1305State struct {
	r0, r1 uint64
	s0, s1 uint64
	h0, h1 uint64
	h2     uint64
	buf    [16]byte
	bufLen int
}

func (p *poly1305State) init(key *[32]byte) {
	p.r0 = binary.LittleEndian.Uint64(key[0:8]) & 0x0ffffffc0fffffff
	p.r1 = binary.LittleEndian.Uint64(key[8:16]) & 0x0ffffffc0ffffffc
	p.s0 = binary.LittleEndian.Uint64(key[16:24])
	p.s1 = binary.LittleEndian.Uint64(key[24:32])
	p.h0, p.h1, p.h2 = 0, 0, 0
	p.bufLen = 0
	clear(p.buf[:])
}

func (p *poly1305State) clear() {
	p.r0, p.r1 = 0, 0
	p.s0, p.s1 = 0, 0
	p.h0, p.h1, p.h2 = 0, 0, 0
	p.bufLen = 0
	clear(p.buf[:])
}

func (p *poly1305State) block(m []byte, hibit uint64) {
	m0 := binary.LittleEndian.Uint64(m[0:8])
	m1 := binary.LittleEndian.Uint64(m[8:16])

	h0, c := bits.Add64(p.h0, m0, 0)
	h1, c := bits.Add64(p.h1, m1, c)
	h2 := p.h2 + hibit + c

	// r1 has its low 2 bits cleared, so r1 + (r1 >> 2) == 5 * (r1 >> 2).
	rr1 := p.r1 + (p.r1 >> 2)

	// (h0 + h1*2^64 + h2*2^128) * (r0 + r1*2^64) mod (2^130 - 5)
	a0hi, a0lo := bits.Mul64(h0, p.r0)
	a1hi, a1lo := bits.Mul64(h1, rr1)
	t0lo, c0 := bits.Add64(a0lo, a1lo, 0)
	t0hi, _ := bits.Add64(a0hi, a1hi, c0)

	b0hi, b0lo := bits.Mul64(h0, p.r1)
	b1hi, b1lo := bits.Mul64(h1, p.r0)
	b2hi, b2lo := bits.Mul64(h2, rr1)
	t1lo, c1 := bits.Add64(b0lo, b1lo, 0)
	t1hi, _ := bits.Add64(b0hi, b1hi, c1)
	t1lo, c1 = bits.Add64(t1lo, b2lo, 0)
	t1hi, _ = bits.Add64(t1hi, b2hi, c1)

	t2 := h2 * p.r0

	h0 = t0lo
	h1, c = bits.Add64(t1lo, t0hi, 0)
	h2 = t2 + t1hi + c

	// Partial reduction: (h2 >> 2) * 2^130 == (h2 >> 2) * 5 = (h2 &^ 3) + (h2 >> 2).
	h2Low := h2 & 3
	h0, c = bits.Add64(h0, h2&^3, 0)
	h1, c = bits.Add64(h1, 0, c)
	h2Low += c

	h0, c = bits.Add64(h0, h2>>2, 0)
	h1, c = bits.Add64(h1, 0, c)
	h2Low += c

	p.h0, p.h1, p.h2 = h0, h1, h2Low
}

func (p *poly1305State) write(data []byte) {
	if p.bufLen > 0 {
		n := copy(p.buf[p.bufLen:], data)
		p.bufLen += n
		data = data[n:]
		if p.bufLen == 16 {
			p.block(p.buf[:], 1)
			p.bufLen = 0
		}
	}
	for len(data) >= 16 {
		p.block(data[:16], 1)
		data = data[16:]
	}
	if len(data) > 0 {
		p.bufLen = copy(p.buf[:], data)
	}
}

func (p *poly1305State) pad16() {
	if p.bufLen == 0 {
		return
	}
	var zeros [16]byte
	p.write(zeros[:16-p.bufLen])
}

func (p *poly1305State) sum(out *[16]byte) {
	if p.bufLen > 0 {
		p.buf[p.bufLen] = 1
		clear(p.buf[p.bufLen+1:])
		p.block(p.buf[:], 0)
		p.bufLen = 0
	}

	// Full reduction mod 2^130 - 5: select g = h + 5 - 2^130 if h >= 2^130 - 5.
	g0, c := bits.Add64(p.h0, 5, 0)
	g1, c := bits.Add64(p.h1, 0, c)
	g2 := p.h2 + c

	mask := -(g2 >> 2)
	h0 := (g0 & mask) | (p.h0 &^ mask)
	h1 := (g1 & mask) | (p.h1 &^ mask)

	h0, c = bits.Add64(h0, p.s0, 0)
	h1, _ = bits.Add64(h1, p.s1, c)

	binary.LittleEndian.PutUint64(out[0:8], h0)
	binary.LittleEndian.PutUint64(out[8:16], h1)
	p.clear()
}
