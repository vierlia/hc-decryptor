package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hcdecryptor/internal/hc"
)

const (
	appName    = "hc-decryptor"
	appVersion = "1.1.0"
	appBlurb   = "inspect, edit & repack HTTP Custom (.hc) configs"
	appAuthor  = "Vierra"
)

type state struct {
	con    *console
	prof   *hc.Profile
	path   string
	dirty  bool
	lastOk bool
}

func Run(path string) error {
	enableVT()
	s := &state{con: openConsole()}
	defer s.con.close()
	if path != "" {
		if err := s.load(path); err != nil {
			s.errLine(err)
		}
	}
	s.banner()
	for {
		s.print("\n")
		raw := s.ask("action", "(1-6, q quit)")
		switch raw {
		case "1":
			s.actOpen()
		case "2":
			s.actDecrypt()
		case "3":
			s.actBypass()
		case "4":
			s.actEdit()
		case "5":
			s.actSave()
		case "6", "q", "quit", "exit":
			return nil
		case "":
			println()
		default:
			s.errLine(fmt.Errorf("unknown action %q", raw))
		}
	}
}

func (s *state) banner() {
	s.print("\x1b[2J\x1b[H\n")
	s.print(panel(cCyan, "", 1, []string{
		bold(appName) + " " + cyan("v"+appVersion),
		dim(appBlurb),
		"",
		dim(padRight("author", 6)) + "  " + magenta(appAuthor),
		dim(padRight("file", 6)) + "  " + s.fileLabel(),
	}))
	s.print("\n")
	s.print(panel(cGray, "choose an action", 0, []string{
		menuRow("1", "OPEN", "buka file .hc"),
		menuRow("2", "DECRYPT", "tampilkan isi config"),
		menuRow("3", "UNLOCK", "clean expiry + HP/akun locks"),
		menuRow("4", "EDIT", "ubah satu field"),
		menuRow("5", "SAVE", "simpan sebagai .hc baru"),
		menuRow("6", "QUIT", "keluar"),
	}))
	s.print("\n")
}

func (s *state) fileLabel() string {
	if s.path == "" {
		return dim("(belum ada file)")
	}
	if s.dirty {
		return cyan(filepath.Base(s.path)) + " " + yellow("*unsaved")
	}
	return cyan(filepath.Base(s.path))
}

func (s *state) actOpen() {
	p := cleanDropped(s.ask("file .hc", "(drag & drop / path)"))
	if isQuit(p) || p == "" {
		return
	}
	if err := s.load(p); err != nil {
		s.errLine(err)
		return
	}
	s.okLine("loaded", filepath.Base(s.path)+"  "+dim(fmt.Sprintf("(%d fields)", len(s.prof.Fields))))
	s.banner()
}

func (s *state) actDecrypt() {
	if !s.needFile() {
		return
	}
	s.print("\n")
	for _, f := range s.prof.Fields {
		if f.Value == "" {
			continue
		}
		s.print("  " + boldYellow(padLeft(fmt.Sprint(f.Index), 2)) + "  " +
			bold(padRight(truncate(f.Name, 24), 24)) + "  " +
			truncate(flat(f.Value), textWidth-32) + "\n")
	}
	s.print("\n")
}

func (s *state) actBypass() {
	if !s.needFile() {
		return
	}
	s.prof.Unlock()
	s.dirty = true
	s.okLine("cleaned", dim("expiry -> lifeTime, HWID/password lock off")+"  "+yellow("(save with 5)"))
}

func (s *state) actEdit() {
	if !s.needFile() {
		return
	}
	s.actDecrypt()
	idx := s.ask("field number", "(q back)")
	if isQuit(idx) || idx == "" {
		return
	}
	i := -1
	for j, f := range s.prof.Fields {
		if fmt.Sprint(f.Index) == idx {
			i = j
			break
		}
	}
	if i < 0 {
		s.errLine(fmt.Errorf("no field %q", idx))
		return
	}
	f := s.prof.Fields[i]
	s.print("  " + dim("current:") + " " + truncate(flat(f.Value), textWidth-12) + "\n")
	val := s.ask(f.Name, "(new value)")
	if isQuit(val) {
		return
	}
	s.prof.Set(i, val)
	s.dirty = true
	s.okLine("edited", bold(f.Name)+" = "+truncate(val, 40))
}

func (s *state) actSave() {
	if !s.needFile() {
		return
	}
	def := strings.TrimSuffix(s.path, filepath.Ext(s.path)) + ".unlocked.hc"
	dst := cleanDropped(s.ask("save as", "(default: "+filepath.Base(def)+")"))
	if isQuit(dst) {
		return
	}
	if dst == "" {
		dst = def
	}
	data, err := s.prof.Repack()
	if err != nil {
		s.errLine(err)
		return
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		s.errLine(err)
		return
	}
	s.dirty = false
	s.okLine("saved", filepath.Base(dst)+"  "+dim(fmt.Sprintf("(%d bytes)", len(data))))
	s.banner()
}

func (s *state) load(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	prof, err := hc.Decrypt(raw)
	if err != nil {
		return err
	}
	s.prof, s.path, s.dirty = prof, path, false
	return nil
}

func (s *state) needFile() bool {
	if s.prof != nil {
		return true
	}
	s.errLine(fmt.Errorf("no file loaded, pick 1 first"))
	return false
}

func (s *state) ask(label, hint string) string {
	s.print(boldCyan("❯") + " " + dim(label) + " " + dim(hint) + " ")
	line, ok := s.con.readLine()
	if !ok {
		return "q"
	}
	return strings.TrimSpace(line)
}

func (s *state) okLine(verb, msg string) {
	s.print("\n  " + green("✓") + " " + green(padRight(verb, 9)) + " " + msg + "\n")
}

func (s *state) errLine(err error) {
	s.print("\n  " + red("✗") + " " + red(padRight("error", 9)) + " " + err.Error() + "\n")
}

func (s *state) print(a string) { fmt.Print(a) }

func isQuit(s string) bool { return s == "q" || s == "quit" || s == "exit" }

func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

func cleanDropped(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i > 0 {
		u := s[i+3:]
		if j := strings.IndexAny(u, `"' `); j >= 0 {
			s = s[:i+3+j]
		}
	}
	if strings.HasPrefix(s, "file:///") {
		s = strings.TrimPrefix(s, "file:///")
	}
	return s
}