//go:build !windows

package tui

import (
	"bufio"
	"os"
	"strings"
	"unicode/utf8"
)

func enableVT() {}

type console struct {
	sc *bufio.Scanner
}

func openConsole() *console {
	return &console{sc: bufio.NewScanner(os.Stdin)}
}

func (c *console) close() {}

func (c *console) readKey() (rune, bool) {
	if !c.sc.Scan() {
		return 0, false
	}
	line := strings.TrimSpace(c.sc.Text())
	if line == "" {
		return '\n', true
	}
	r, _ := utf8.DecodeRuneInString(line)
	return r, true
}

func (c *console) readLine() (string, bool) {
	if !c.sc.Scan() {
		return "", false
	}
	return strings.TrimSpace(c.sc.Text()), true
}