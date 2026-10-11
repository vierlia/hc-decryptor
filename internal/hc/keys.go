package hc

import "encoding/hex"

var (
	xorFile    = mustHex("e382e4b8adc386f09f9293")
	staticNonce = []byte{0xdb, 0xdb, 0xdb, 0xdb, 0xdb, 0xdb, 0xdb, 0xdb}

	chachaKeys = [][]byte{
		mustHex("2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d"),
		mustHex("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"),
		mustHex("cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3"),
		mustHex("4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193"),
		mustHex("f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63"),
		mustHex("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"),
		mustHex("45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944"),
		mustHex("3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"),
	}

	rstKeys = [][]byte{
		[]byte("JN1k3YHc2.6_v235"), []byte("JN1k3YHc_2.7_v71"),
		[]byte("JN1k3YHc2.7.ps69"), []byte("JN1k3YHc2.7.6950"),
		[]byte("Jn1K3yHc2.8.ps08"), []byte("Jn1K3yHc2.9.ps6c"),
		[]byte("Zk:L7>WKaiK*s9>D"), []byte("!<f!&WIlM**R.B0X"),
		[]byte("b4a5opinx2uloec6"),
	}

	rstXORKey = []byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}

	jklKeyOld = []byte{0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0, 0xcf, 0xce, 0xcd, 0xcc,
		0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 0xb7, 0xb6, 0xb5, 0xb4}
	jklKeyNew = []byte{8, 9, 10, 11, 12, 13, 14, 15, 17, 17, 5, 4, 3, 2, 1, 0, 255, 254, 253, 252}
)

const (
	keyIndexOuter   = 5
	keyIndexContent = 1
	keyIndexField   = 7
)

var tokenMap = []string{
	"payload", "proxy", "lockAllConfig", "blockedByRoot", "expiryTime",
	"noteEnabled", "notes", "sshField", "mobileDataAndLockProvider", "unlockUserAndPass",
	"ovpnConfig", "ovpnUserAndPass", "sni", "unlockUserAndPass2", "unknown14",
	"blockedByHwid", "cloudconfig", "psiphon", "name", "blockArea",
	"connectionMode", "blockedByPassword", "unknown22", "extraSniffer", "psiphon2",
	"v2rayEnabled", "v2rayConfig", "version", "slowdnsEnabled", "slowdnsServer",
	"slowdnsPublickey", "dnsResolver",
}

func fieldName(i int) string {
	if i < len(tokenMap) {
		return tokenMap[i]
	}
	return "field_" + itoa(i)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("hc: bad hex key: " + err.Error())
	}
	return b
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}