package cilbpf

import (
	"testing"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/bpf"
)

// TestExecProofOfConcept verifies the cilium/ebpf exec source mirrors the legacy gobpf API.
func TestExecProofOfConcept(t *testing.T) {
	t.Helper()
	testEventSourcePoC(t, "exec", ExecBPF, bpf.ExecBPF, LoadExecSpec)
}

// TestOpenProofOfConcept verifies the cilium/ebpf open source mirrors the legacy gobpf API.
func TestOpenProofOfConcept(t *testing.T) {
	t.Helper()
	testEventSourcePoC(t, "open", OpenBPF, bpf.OpenBPF, LoadOpenSpec)
}

// TestListenProofOfConcept verifies the cilium/ebpf listen source mirrors the legacy gobpf API.
func TestListenProofOfConcept(t *testing.T) {
	t.Helper()
	testEventSourcePoC(t, "listen", ListenBPF, bpf.ListenBPF, LoadListenSpec)
}

// TestReadlineProofOfConcept verifies the cilium/ebpf readline source mirrors the legacy gobpf API.
func TestReadlineProofOfConcept(t *testing.T) {
	t.Helper()
	testEventSourcePoC(t, "readline", ReadlineBPF, bpf.ReadlineBPF, LoadReadlineSpec)
}

func testEventSourcePoC(
	t *testing.T,
	name string,
	ciliumSource func(chan events.Event, events.Ctx),
	legacySource func(chan events.Event, events.Ctx),
	loadSpec func() error,
) {
	t.Helper()

	if ciliumSource == nil || legacySource == nil {
		t.Fatalf("%s event sources must be non-nil", name)
	}

	if err := loadSpec(); err != nil {
		t.Fatalf("Load%sSpec() error: %v", name, err)
	}
}
