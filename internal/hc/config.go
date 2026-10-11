package hc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

type Field struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	Value string `json:"value"`

	raw  string
	orig string
	mode int
	tail []byte
}

const (
	emptyMarker = "302fe48d31a80b905c19af9d4edfe9c3"
	watermark   = "88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d"
)

const (
	modePlain = iota
	modeHexChaCha
	modeHexChaChaJKL
	modeJKL
	modeUnknown
)

type Profile struct {
	Fields []Field `json:"fields"`

	Split  string
	IsNew  bool
	meta   map[string]string
	outer  map[string]any
	xyTop  bool
	tokens []string
	changed bool
}

func Decrypt(raw []byte) (*Profile, error) {
	hexPayload := fileToHex(raw)

	outerTxt := abDecrypt(hexPayload, chachaKeys[keyIndexOuter], staticNonce)
	if !strings.HasPrefix(outerTxt, "{") {
		for _, k := range chachaKeys {
			if t := abDecrypt(hexPayload, k, staticNonce); strings.HasPrefix(t, "{") {
				outerTxt = t
				break
			}
		}
	}
	if !strings.HasPrefix(outerTxt, "{") {
		return nil, errors.New("cannot read outer layer (not a .hc file or unknown key)")
	}

	var outer map[string]any
	if err := json.Unmarshal([]byte(outerTxt), &outer); err != nil {
		return nil, err
	}

	p := &Profile{outer: outer, meta: map[string]string{}}
	objA, _ := outer["a"].(map[string]any)
	cfgObj, isCfg := outer["cfg"].(map[string]any)
	p.IsNew = isCfg && cfgObj["content"] != nil

	var target string
	if p.IsNew {
		for k, name := range map[string]string{"b": "hwid", "f": "area"} {
			if v := strOf(first(outer[k], cfgObj[k])); v != "" {
				p.meta[name] = v
			}
		}
		p.Split = "[splitConfig]"
		target = strOf(cfgObj["content"])
	} else {
		for k, name := range map[string]string{"bb": "hwid", "e": "password", "fe": "area", "ed": "provider"} {
			v := outer[k]
			if k != "e" {
				v = objA[k]
			}
			if dv := abDecrypt(strOf(v), chachaKeys[keyIndexField], staticNonce); dv != "" {
				p.meta[name] = dv
			}
		}
		if t := strOf(outer["xy"]); t != "" {
			target, p.xyTop = t, true
		} else {
			target = strOf(objA["xy"])
		}
		p.Split = strOf(outer["uv"])
		if p.Split == "" {
			p.Split = strOf(objA["uv"])
		}
	}
	if target == "" || p.Split == "" {
		return nil, errors.New("content not found in outer JSON")
	}

	content := ""
	if p.IsNew {
		if s, ok := rstDecrypt(target); ok {
			content = s
		} else {
			for _, k := range chachaKeys {
				if t := abDecrypt(target, k, staticNonce); strings.Contains(t, p.Split) {
					content = t
					break
				}
			}
		}
	} else {
		content = abDecrypt(target, chachaKeys[keyIndexContent], staticNonce)
	}
	if content == "" {
		return nil, errors.New("content not decrypted")
	}

	nonce := p.dynamicNonce()
	p.tokens = strings.Split(content, p.Split)
	for i, tok := range p.tokens {
		f := Field{Index: i, Name: fieldName(i), raw: tok}
		f.Value, f.mode, f.tail = p.decodeToken(tok, nonce)
		if f.Value == emptyMarker {
			f.Value = ""
		}
		f.Value = strings.ReplaceAll(f.Value, watermark, "")
		if hasCtrl(f.Value) {
			f.Value = ""
		}
		f.orig = f.Value
		p.Fields = append(p.Fields, f)
	}
	return p, nil
}

func (p *Profile) decodeToken(tok string, nonce []byte) (string, int, []byte) {
	if tok == "" || tok == "true" || tok == "false" || tok == "lifeTime" ||
		tok == "[splitPsiphon][splitPsiphon]" || strings.HasPrefix(tok, "<") {
		return tok, modePlain, nil
	}
	if isHexToken(tok) && len(tok) >= 32 {
		data, err := hex.DecodeString(tok)
		if err == nil && len(data) > 16 {
			c := newChaCha(chachaKeys[keyIndexField], nonce, 1)
			out := make([]byte, len(data)-16)
			c.XORKeyStream(out, data[:len(data)-16])
			dec := string(out)
			if j := jklDecrypt(dec, false); j != dec && isPrintable(j) {
				return j, modeHexChaChaJKL, data[len(data)-16:]
			}
			if dec != "" {
				return dec, modeHexChaCha, data[len(data)-16:]
			}
		}
		return "", modeUnknown, nil
	}
	if j := jklDecrypt(tok, p.IsNew); j != tok && isPrintable(j) {
		return j, modeJKL, nil
	}
	return tok, modePlain, nil
}

func (p *Profile) Set(i int, value string) {
	if i < 0 || i >= len(p.Fields) {
		return
	}
	p.Fields[i].Value = value
	p.changed = true
}

func (p *Profile) Unlock() {
	byIdx := map[int]string{
		2:  "false",
		4:  "lifeTime",
		9:  "true",
		15: "false",
		21: "false",
	}
	for i, v := range byIdx {
		if i < len(p.Fields) {
			p.Set(i, v)
		}
	}
}

func (p *Profile) Repack() ([]byte, error) {
	nonce := p.dynamicNonce()
	toks := make([]string, len(p.tokens))
	copy(toks, p.tokens)
	for i := range p.Fields {
		f := &p.Fields[i]
		toks[f.Index] = p.encodeToken(f, nonce)
	}

	var content strings.Builder
	for i, t := range toks {
		if i > 0 {
			content.WriteString(p.Split)
		}
		content.WriteString(t)
	}

	if p.IsNew {
		return nil, errors.New("repack for the new format is not supported yet")
	}
	ctXY := abEncrypt(content.String(), chachaKeys[keyIndexContent], staticNonce, nil)
	if objA, ok := p.outer["a"].(map[string]any); ok && !p.xyTop {
		objA["xy"] = ctXY
	} else {
		p.outer["xy"] = ctXY
	}
	for _, k := range []string{"bb", "e", "fe", "ed"} {
		if _, ok := p.outer[k]; ok {
			p.outer[k] = ""
		}
		if objA, ok := p.outer["a"].(map[string]any); ok {
			if _, ok := objA[k]; ok {
				objA[k] = ""
			}
		}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p.outer); err != nil {
		return nil, err
	}
	outerTxt := strings.TrimRight(buf.String(), "\n")
	ctOuter := abEncrypt(outerTxt, chachaKeys[keyIndexOuter], staticNonce, nil)
	return hexToFile(ctOuter), nil
}

func (p *Profile) encodeToken(f *Field, nonce []byte) string {
	if f.Value == f.orig {
		return f.raw
	}
	switch f.mode {
	case modePlain:
		return f.Value
	case modeJKL:
		return jklEncrypt(f.Value, p.IsNew)
	case modeHexChaCha:
		return abEncrypt(f.Value, chachaKeys[keyIndexField], nonce, f.tail)
	case modeHexChaChaJKL:
		return abEncrypt(jklEncrypt(f.Value, false), chachaKeys[keyIndexField], nonce, f.tail)
	default:
		return f.raw
	}
}

func (p *Profile) dynamicNonce() []byte {
	n := make([]byte, 8)
	copy(n, staticNonce)
	hexOf := func(s string) string { return hex.EncodeToString([]byte(s)) }
	h, pw, pr, a := p.meta["hwid"], p.meta["password"], p.meta["provider"], p.meta["area"]
	var derived string
	if h != "" && pw == "" && pr == "" && a == "" {
		derived = hexOf(h) + hexOf(h)
	} else {
		derived = hexOf(pw) + hexOf(h) + hexOf(pr) + hexOf(a)
	}
	if derived != "" {
		if b, err := hex.DecodeString(derived); err == nil && len(b) > 0 {
			copy(n, b)
		}
	}
	return n
}

func isPrintable(s string) bool {
	if s == "" {
		return false
	}
	ok := 0
	for _, r := range s {
		if r >= 32 && r < 127 || r == '\n' || r == '\r' || r == '\t' {
			ok++
		}
	}
	return ok*100/len(s) >= 85
}

func hasCtrl(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return true
		}
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return true
		}
	}
	return false
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

func first(vs ...any) any {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}