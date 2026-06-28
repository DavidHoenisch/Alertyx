package cilbpf

import (
	"testing"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/bpf"
)

// TestExecProofOfConcept verifies the cilium/ebpf exec source mirrors the legacy gobpf API.
func TestExecProofOfConcept(t *testing.T) {
	t.Helper()

	var ciliumSource func(chan events.Event, events.Ctx) = ExecBPF
	var legacySource func(chan events.Event, events.Ctx) = bpf.ExecBPF

	if ciliumSource == nil || legacySource == nil {
		t.Fatal("exec event sources must be non-nil")
	}

	if err := LoadExecSpec(); err != nil {
		t.Fatalf("LoadExecSpec() error: %v", err)
	}
}
