package tui

import "strings"

const panelWidth = 62

const textWidth = panelWidth - 6

const (
	cReset   = "\x1b[0m"
	cBold    = "\x1b[1m"
	cDim     = "\x1b[2m"
	cRed     = "\x1b[31m"
	cGreen   = "\x1b[32m"
	cYellow  = "\x1b[33m"
	cCyan    = "\x1b[36m"
	cMagenta = "\x1b[35m"
	cGray    = "\x1b[90m"
)

func bold(s string) string    { return cBold + s + cReset }
func dim(s string) string     { return cDim + s + cReset }
func red(s string) string     { return cRed + s + cReset }
func green(s string) string   { return cGreen + s + cReset }
func yellow(s string) string  { return cYellow + s + cReset }
func cyan(s string) string    { return cCyan + s + cReset }
func magenta(s string) string { return cMagenta + s + cReset }
func gray(s string) string    { return cGray + s + cReset }

func boldCyan(s string) string  { return cBold + cCyan + s + cReset }
func boldYellow(s string) string { return cBold + cYellow + s + cReset }

func visLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		switch {
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		case r == '\x1b':
			inEsc = true
		default:
			n++
		}
	}
	return n
}

func runes(s string) int { return len([]rune(s)) }

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n < 1 {
		return ""
	}
	return string(r[:n-1]) + "…"
}

func padTo(s string, n int) string {
	d := n - visLen(s)
	if d <= 0 {
		return s
	}
	return s + strings.Repeat(" ", d)
}

func padRight(s string, n int) string {
	if runes(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-runes(s))
}

func padLeft(s string, n int) string {
	if runes(s) >= n {
		return s
	}
	return strings.Repeat(" ", n-runes(s)) + s
}

func panel(borderColor, title string, padRows int, lines []string) string {
	var b strings.Builder
	var bar string

	if title != "" {
		d := panelWidth - 5 - runes(title)
		bar = "┌─" + " " + title + " " + strings.Repeat("─", nextZero(d)) + "┐"
	} else {
		bar = "┌" + strings.Repeat("─", panelWidth-2) + "┐"
	}
	b.WriteString(borderColor + bar + cReset + "\n")

	blank := "│" + strings.Repeat(" ", panelWidth-2) + "│"
	for i := 0; i < padRows; i++ {
		b.WriteString(borderColor + blank + cReset + "\n")
	}
	for _, ln := range lines {
		row := "│" + "  " + padTo(ln, textWidth) + "  " + "│"
		b.WriteString(borderColor + row + cReset + "\n")
	}
	for i := 0; i < padRows; i++ {
		b.WriteString(borderColor + blank + cReset + "\n")
	}

	b.WriteString(borderColor + "└" + strings.Repeat("─", panelWidth-2) + "┘" + cReset)
	return b.String()
}

func nextZero(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func menuRow(num, label, hint string) string {
	return "  " + boldYellow(num) + "  " + bold(padRight(label, 9)) + "  " + dim(hint)
}