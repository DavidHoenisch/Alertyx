//go:build integration

package integration

import (
	"os"
	"testing"
	"time"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/cilbpf"
)

func TestIntegrationCilBPFExecCapture(t *testing.T) {
	SkipUnlessIntegration(t)
	SkipUnlessRoot(t)

	h := NewHarness(t)
	defer h.Stop()

	if err := h.Start(cilbpf.ExecBPF); err != nil {
		t.Fatalf("Start: %v", err)
	}

	parentPID := uint32(os.Getpid())
	if err := h.RunCmd("/bin/true"); err != nil {
		t.Fatalf("RunCmd: %v", err)
	}

	deadline := time.Now().Add(DefaultCollectTimeout)
	for time.Now().Before(deadline) {
		for _, ev := range h.Collected() {
			execEv, ok := ev.(*events.Exec)
			if !ok || execEv.IsPwd() || execEv.IsOther() {
				continue
			}
			if !execEv.IsRet() {
				continue
			}
			if execEv.FetchPid() == parentPID {
				continue
			}
			if execEv.FetchPpid() != parentPID {
				t.Fatalf("exec event pid=%d ppid=%d, want ppid=%d",
					execEv.FetchPid(), execEv.FetchPpid(), parentPID)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("no exec event with ppid=%d collected within %s; got %d events",
		parentPID, DefaultCollectTimeout, len(h.Collected()))
}
