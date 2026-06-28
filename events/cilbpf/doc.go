// Package cilbpf provides a cilium/ebpf proof-of-concept for Alertyx event sources.
//
// Regenerate embedded BPF objects after editing src/*.c:
//
//	go generate ./...
package cilbpf

//go:generate go run generate.go
