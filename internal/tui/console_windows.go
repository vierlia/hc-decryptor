//go:build windows

package tui

import (
	"os"
	"syscall"
	"unicode/utf8"
	"unsafe"
)

var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	procGetMode  = kernel32.NewProc("GetConsoleMode")
	procSetMode  = kernel32.NewProc("SetConsoleMode")
	procReadFile = kernel32.NewProc("ReadFile")
)

const (
	wLineInput = 0x0002
	wEchoInput = 0x0004
	wVTProcess = 0x0004
)

func enableVT() {
	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	if r, _, _ := procGetMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode))); r != 0 {
		procSetMode.Call(uintptr(h), uintptr(mode|wVTProcess))
	}
}

type console struct {
	h     syscall.Handle
	saved uint32
}

func openConsole() *console {
	h := syscall.Handle(os.Stdin.Fd())
	var mode uint32
	procGetMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	procSetMode.Call(uintptr(h), uintptr(mode&^(wLineInput|wEchoInput)))
	return &console{h: h, saved: mode}
}

func (c *console) close() {
	procSetMode.Call(uintptr(c.h), uintptr(c.saved))
}

func (c *console) readByte() (byte, bool) {
	var buf [1]byte
	var n uint32
	r, _, _ := procReadFile.Call(uintptr(c.h), uintptr(unsafe.Pointer(&buf[0])), 1, uintptr(unsafe.Pointer(&n)), 0)
	if r == 0 || n == 0 {
		return 0, false
	}
	return buf[0], true
}

func (c *console) readKey() (rune, bool) {
	b, ok := c.readByte()
	if !ok {
		return 0, false
	}
	if b < utf8.RuneSelf {
		return rune(b), true
	}
	buf := []byte{b}
	for !utf8.FullRune(buf) {
		nb, ok := c.readByte()
		if !ok {
			break
		}
		buf = append(buf, nb)
	}
	r, _ := utf8.DecodeRune(buf)
	return r, true
}

func (c *console) readLine() (string, bool) {
	var out []rune
	for {
		r, ok := c.readKey()
		if !ok {
			return string(out), false
		}
		switch r {
		case '\r', '\n':
			os.Stdout.WriteString("\n")
			return string(out), true
		case 3:
			return "", false
		case 8, 127:
			if len(out) > 0 {
				out = out[:len(out)-1]
				os.Stdout.WriteString("\b \b")
			}
		default:
			if r >= 32 {
				out = append(out, r)
				var rb [4]byte
				n := utf8.EncodeRune(rb[:], r)
				os.Stdout.Write(rb[:n])
			}
		}
	}
}