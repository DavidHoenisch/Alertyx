//go:build ignore

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	root := repoRoot()
	cilbpf := filepath.Join(root, "events", "cilbpf")
	src := filepath.Join(cilbpf, "src")

	if err := runBPF2GO(root, src, cilbpf); err != nil {
		fmt.Fprintf(os.Stderr, "bpf2go: %v\n", err)
		os.Exit(1)
	}
}

func runBPF2GO(root, src, cilbpf string) error {
	args := []string{
		"run", "github.com/cilium/ebpf/cmd/bpf2go",
		"-go-package", "bpf",
		"-no-global-types",
		"-type", "event_t",
		"-output-dir", filepath.Join(cilbpf, "bpf"),
		"-output-stem", "exec",
		"exec",
		filepath.Join(src, "exec.c"),
		"--",
		"-I" + filepath.Join(cilbpf, "headers"),
		"-I" + src,
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func repoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getwd: %v\n", err)
		os.Exit(1)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			fmt.Fprintln(os.Stderr, "go.mod not found")
			os.Exit(1)
		}
		dir = parent
	}
}
