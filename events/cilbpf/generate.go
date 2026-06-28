//go:build ignore

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type bpfTarget struct {
	stem string
	src  string
	typ  string
}

var bpfTargets = []bpfTarget{
	{stem: "exec", src: "exec.c", typ: "event_t"},
	{stem: "open", src: "open.c", typ: "open_event_t"},
	{stem: "listen", src: "listen.c", typ: "listen_event_t"},
	{stem: "readline", src: "readline.c", typ: "readline_event_t"},
}

func main() {
	root := repoRoot()
	cilbpf := filepath.Join(root, "events", "cilbpf")
	src := filepath.Join(cilbpf, "src")

	for _, target := range bpfTargets {
		if err := runBPF2GO(root, src, cilbpf, target); err != nil {
			fmt.Fprintf(os.Stderr, "bpf2go %s: %v\n", target.stem, err)
			os.Exit(1)
		}
	}
}

func runBPF2GO(root, src, cilbpf string, target bpfTarget) error {
	archDefine := bpfTargetArchDefine()
	if archDefine == "" {
		return fmt.Errorf("unsupported GOARCH %s for bpf2go", runtime.GOARCH)
	}

	args := []string{
		"run", "github.com/cilium/ebpf/cmd/bpf2go",
		"-go-package", "bpf",
		"-no-global-types",
		"-type", target.typ,
		"-output-dir", filepath.Join(cilbpf, "bpf"),
		"-output-stem", target.stem,
		target.stem,
		filepath.Join(src, target.src),
		"--",
		"-I" + filepath.Join(cilbpf, "headers"),
		"-I" + src,
		"-D" + archDefine,
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func bpfTargetArchDefine() string {
	switch runtime.GOARCH {
	case "amd64", "386":
		return "__TARGET_ARCH_x86"
	case "arm64":
		return "__TARGET_ARCH_arm64"
	case "arm":
		return "__TARGET_ARCH_arm"
	case "ppc64le":
		return "__TARGET_ARCH_powerpc"
	case "mips64le", "mipsle":
		return "__TARGET_ARCH_mips"
	case "riscv64":
		return "__TARGET_ARCH_riscv"
	case "s390x":
		return "__TARGET_ARCH_s390"
	default:
		return ""
	}
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
