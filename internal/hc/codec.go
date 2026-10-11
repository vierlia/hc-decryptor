package hc

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

func fileToHex(raw []byte) string {
	d := utf8ToLatin1(raw)
	out := make([]byte, len(d))
	for i, b := range d {
		out[i] = b ^ xorFile[i%len(xorFile)]
	}
	return string(out)
}

func hexToFile(hexStr string) []byte {
	d := make([]byte, len(hexStr))
	for i := 0; i < len(hexStr); i++ {
		d[i] = hexStr[i] ^ xorFile[i%len(xorFile)]
	}
	return latin1ToUTF8(d)
}

func utf8ToLatin1(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		r, size := decodeRune(raw[i:])
		if r >= 0 && r < 256 {
			out = append(out, byte(r))
		}
		i += size
	}
	return out
}

func latin1ToUTF8(d []byte) []byte {
	var buf bytes.Buffer
	for _, b := range d {
		buf.WriteRune(rune(b))
	}
	return buf.Bytes()
}

func abDecrypt(hexStr string, key, nonce []byte) string {
	data, err := hex.DecodeString(cleanHex(hexStr))
	if err != nil || len(data) <= 16 {
		return ""
	}
	c := newChaCha(key, nonce, 1)
	out := make([]byte, len(data)-16)
	c.XORKeyStream(out, data[:len(data)-16])
	return string(out)
}

func abEncrypt(plain string, key, nonce, tail []byte) string {
	if len(tail) != 16 {
		tail = make([]byte, 16)
	}
	c := newChaCha(key, nonce, 1)
	ct := make([]byte, len(plain))
	c.XORKeyStream(ct, []byte(plain))
	return hex.EncodeToString(append(ct, tail...))
}

func rstDecrypt(encrypted string) (string, bool) {
	x := make([]byte, len(encrypted))
	for i, b := range []byte(encrypted) {
		x[i] = b ^ rstXORKey[i%len(rstXORKey)]
	}
	ct, err := base64.StdEncoding.DecodeString(string(x))
	if err != nil {
		return "", false
	}
	for _, k := range rstKeys {
		pt, err := aesECBDecrypt(k, ct)
		if err != nil {
			continue
		}
		if s := unpadPKCS7(pt); strings.Contains(string(s), "[splitConfig]") {
			return string(s), true
		}
	}
	return "", false
}

func aesECBDecrypt(key, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("not an AES block multiple")
	}
	pt := make([]byte, len(ct))
	for i := 0; i < len(ct); i += aes.BlockSize {
		block.Decrypt(pt[i:], ct[i:])
	}
	return pt, nil
}

func unpadPKCS7(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	p := int(b[len(b)-1])
	if p == 0 || p > aes.BlockSize || p > len(b) {
		return b
	}
	return b[:len(b)-p]
}

func jklDecrypt(s string, isNew bool) string {
	key := jklKeyOld
	if isNew {
		key = jklKeyNew
	}
	padded := s
	if m := len(s) % 4; m != 0 {
		padded += strings.Repeat("=", 4-m)
	}
	data, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		return s
	}
	for i, d := range data {
		k := key[i%len(key)]
		data[i] = (((d ^ 0xff) & 0xca) | (d & 0x35)) ^ (((k ^ 0xff) & 0xca) | (k & 0x35))
	}
	inner, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return s
	}
	return string(inner)
}

func jklEncrypt(plain string, isNew bool) string {
	key := jklKeyOld
	if isNew {
		key = jklKeyNew
	}
	inner := []byte(base64.StdEncoding.EncodeToString([]byte(plain)))
	for i, d := range inner {
		k := key[i%len(key)]
		inner[i] = (((d ^ 0xff) & 0xca) | (d & 0x35)) ^ (((k ^ 0xff) & 0xca) | (k & 0x35))
	}
	return base64.StdEncoding.EncodeToString(inner)
}

var reZ3a = regexp.MustCompile(`(-?\d+)\.(-?\d+)`)
var reCredSSH = regexp.MustCompile(`^([\w.-]+):([\d-]+)@(.+):(.+)$`)
var reCredPlain = regexp.MustCompile(`^([^:]+):(.+)$`)

func extractZ3a(enc string) string {
	var out []byte
	for _, m := range reZ3a.FindAllStringSubmatch(enc, -1) {
		a, b := atoi(m[1]), atoi(m[2])
		if b >= 0 && b < 64 {
			out = append(out, byte((a>>b)&0xff))
		}
	}
	return string(out)
}

func processCredentials(raw string, isSSH bool) string {
	var m []string
	if isSSH {
		m = reCredSSH.FindStringSubmatch(raw)
	} else {
		m = reCredPlain.FindStringSubmatch(raw)
	}
	if m == nil {
		return raw
	}
	u, p := m[len(m)-2], m[len(m)-1]
	if d := extractZ3a(u); d != "" {
		u = d
	}
	if d := extractZ3a(p); d != "" {
		p = d
	}
	if isSSH {
		return m[1] + ":" + m[2] + "@" + u + ":" + p
	}
	return u + ":" + p
}

func cleanHex(s string) string {
	var buf bytes.Buffer
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

func isHexToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func atoi(s string) int {
	n := 0
	neg := false
	for i, r := range s {
		if i == 0 && r == '-' {
			neg = true
			continue
		}
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	if neg {
		return -n
	}
	return n
}

func decodeRune(b []byte) (rune, int) {
	if len(b) == 0 {
		return -1, 0
	}
	c := b[0]
	switch {
	case c < 0x80:
		return rune(c), 1
	case c < 0xc2:
		return rune(c), 1
	case c < 0xe0:
		if len(b) < 2 {
			return -1, 1
		}
		return rune(c&0x1f)<<6 | rune(b[1]&0x3f), 2
	case c < 0xf0:
		if len(b) < 3 {
			return -1, 1
		}
		return rune(c&0x0f)<<12 | rune(b[1]&0x3f)<<6 | rune(b[2]&0x3f), 3
	default:
		if len(b) < 4 {
			return -1, 1
		}
		return rune(c&0x07)<<18 | rune(b[1]&0x3f)<<12 | rune(b[2]&0x3f)<<6 | rune(b[3]&0x3f), 4
	}
}