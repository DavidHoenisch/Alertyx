//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cilium/ebpf/btf"
)

func main() {
	root := repoRoot()
	cilbpf := filepath.Join(root, "events", "cilbpf")
	src := filepath.Join(cilbpf, "src")

	if err := writeOffsets(filepath.Join(src, "offsets.h")); err != nil {
		fmt.Fprintf(os.Stderr, "write offsets: %v\n", err)
		os.Exit(1)
	}

	if err := runBPF2GO(root, src, cilbpf); err != nil {
		fmt.Fprintf(os.Stderr, "bpf2go: %v\n", err)
		os.Exit(1)
	}
}

func writeOffsets(path string) error {
	spec, err := btf.LoadSpec("/sys/kernel/btf/vmlinux")
	if err != nil {
		return fmt.Errorf("load kernel BTF: %w", err)
	}

	offsets := map[string]uint32{
		"TASK_REAL_PARENT_OFF":   memberOffset(spec, "task_struct", "real_parent"),
		"TASK_FS_OFF":            memberOffset(spec, "task_struct", "fs"),
		"TASK_TGID_OFF":          memberOffset(spec, "task_struct", "tgid"),
		"FS_PWD_OFF":             memberOffset(spec, "fs_struct", "pwd"),
		"PATH_DENTRY_OFF":        memberOffset(spec, "path", "dentry"),
		"DENTRY_D_NAME_OFF":      memberOffset(spec, "dentry", "d_name"),
		"DENTRY_SHORTNAME_OFF":   memberOffset(spec, "dentry", "d_shortname"),
		"DENTRY_D_PARENT_OFF":    memberOffset(spec, "dentry", "d_parent"),
		"QSTR_NAME_OFF":          memberOffset(spec, "qstr", "name"),
	}

	var buf bytes.Buffer
	buf.WriteString(`// SPDX-License-Identifier: GPL-2.0
// Kernel struct offsets generated from /sys/kernel/btf/vmlinux.
// Regenerate with: go run generate.go

#ifndef ALERTYX_CILBPF_OFFSETS_H
#define ALERTYX_CILBPF_OFFSETS_H

`)
	for name, off := range offsets {
		fmt.Fprintf(&buf, "#define %s %d\n", name, off)
	}
	buf.WriteString("\n#endif\n")

	return os.WriteFile(path, buf.Bytes(), 0644)
}

func memberOffset(spec *btf.Spec, structName, memberName string) uint32 {
	var st *btf.Struct
	if err := spec.TypeByName(structName, &st); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s.%s: %v\n", structName, memberName, err)
		return 0
	}
	for _, member := range st.Members {
		if member.Name == memberName {
			return uint32(member.Offset.Bytes())
		}
	}
	fmt.Fprintf(os.Stderr, "warning: member %s not found in %s\n", memberName, structName)
	return 0
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
