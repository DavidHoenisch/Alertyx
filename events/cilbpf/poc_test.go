package cilbpf

import (
	"testing"

	"github.com/DavidHoenisch/Alertyx/events"
)

func TestExecProofOfConcept(t *testing.T) {
	t.Helper()
	testEventSourcePoC(t, "exec", ExecBPF, LoadExecSpec)
}

func TestOpenProofOfConcept(t *testing.T) {
	t.Helper()
	testEventSourcePoC(t, "open", OpenBPF, LoadOpenSpec)
}

func TestListenProofOfConcept(t *testing.T) {
	t.Helper()
	testEventSourcePoC(t, "listen", ListenBPF, LoadListenSpec)
}

func TestReadlineProofOfConcept(t *testing.T) {
	t.Helper()
	testEventSourcePoC(t, "readline", ReadlineBPF, LoadReadlineSpec)
}

func testEventSourcePoC(
	t *testing.T,
	name string,
	source func(chan events.Event, events.Ctx),
	loadSpec func() error,
) {
	t.Helper()

	if source == nil {
		t.Fatalf("%s event source must be non-nil", name)
	}

	if err := loadSpec(); err != nil {
		t.Fatalf("Load%sSpec() error: %v", name, err)
	}
}
