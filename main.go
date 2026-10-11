package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hcdecryptor/internal/hc"
	"hcdecryptor/internal/tui"
)

func main() {
	jsonOut := flag.Bool("json", false, "print decrypted config as JSON and exit")
	unlock := flag.Bool("unlock", false, "strip protections and write a new .hc")
	out := flag.String("o", "", "output path for -unlock")
	name := flag.String("name", "", "rename the config (used with -unlock)")
	flag.Parse()

	if flag.NArg() == 0 {
		if err := tui.Run(""); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	path := flag.Arg(0)
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	prof, err := hc.Decrypt(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	switch {
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		_ = enc.Encode(prof.Fields)
	case *unlock:
		prof.Unlock()
		if *name != "" {
			for i := range prof.Fields {
				if prof.Fields[i].Name == "name" {
					prof.Set(i, *name)
				}
			}
		}
		data, err := prof.Repack()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		dst := *out
		if dst == "" {
			dst = strings.TrimSuffix(path, filepath.Ext(path)) + ".unlocked.hc"
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Println("written:", dst)
	default:
		if err := tui.Run(path); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
}