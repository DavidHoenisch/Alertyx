// Package cilbpf provides a cilium/ebpf proof-of-concept for Alertyx event sources.
//
// Regenerate embedded BPF objects after editing src/*.c:
//
//	go generate ./events/cilbpf/...
//
// Generation uses bpf2go for exec, open, listen, and readline; run on the target
// CPU architecture so kprobe register layouts match the deployment kernel.
package cilbpf

//go:generate go run generate.go
