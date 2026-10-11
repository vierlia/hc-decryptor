package hc

import "encoding/binary"

type chacha struct {
	key   [8]uint32
	nonce [2]uint32
	ctr   uint64
	ks    [64]byte
	off   int
}

func newChaCha(key, nonce8 []byte, startCtr uint64) *chacha {
	c := &chacha{ctr: startCtr, off: 64}
	for i := 0; i < 8; i++ {
		c.key[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	c.nonce[0] = binary.LittleEndian.Uint32(nonce8[0:4])
	c.nonce[1] = binary.LittleEndian.Uint32(nonce8[4:8])
	return c
}

func (c *chacha) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		if c.off == 64 {
			c.genBlock()
			c.off = 0
		}
		dst[i] = src[i] ^ c.ks[c.off]
		c.off++
	}
}

func rotl(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }

func qr(w *[16]uint32, a, b, c, d int) {
	w[a] += w[b]
	w[d] ^= w[a]
	w[d] = rotl(w[d], 16)
	w[c] += w[d]
	w[b] ^= w[c]
	w[b] = rotl(w[b], 12)
	w[a] += w[b]
	w[d] ^= w[a]
	w[d] = rotl(w[d], 8)
	w[c] += w[d]
	w[b] ^= w[c]
	w[b] = rotl(w[b], 7)
}

func (c *chacha) genBlock() {
	s := [16]uint32{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		c.key[0], c.key[1], c.key[2], c.key[3],
		c.key[4], c.key[5], c.key[6], c.key[7],
		uint32(c.ctr), uint32(c.ctr >> 32), c.nonce[0], c.nonce[1],
	}
	w := s
	for i := 0; i < 10; i++ {
		qr(&w, 0, 4, 8, 12)
		qr(&w, 1, 5, 9, 13)
		qr(&w, 2, 6, 10, 14)
		qr(&w, 3, 7, 11, 15)
		qr(&w, 0, 5, 10, 15)
		qr(&w, 1, 6, 11, 12)
		qr(&w, 2, 7, 8, 13)
		qr(&w, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(c.ks[i*4:], w[i]+s[i])
	}
	c.ctr++
}