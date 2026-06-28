package analysis

import (
	"testing"
	"time"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/techs"
)

func copyCString(dst []byte, s string) {
	copy(dst, s)
	if len(s) < len(dst) {
		dst[len(s)] = 0
	}
}

func TestDetectionToDetectionEvent(t *testing.T) {
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	openEv := &events.Open{}
	openEv.Pid = 12345
	openEv.Ppid = 1
	openEv.Uid = 0
	copyCString(openEv.Pwd[:], "/home/attacker")
	copyCString(openEv.Filename[:], "/etc/shadow")

	det := &Detection{
		Time:  ts,
		Level: techs.LevelWarn,
		Tech:  techs.L1002{},
		Artifacts: []events.LogItem{
			{Time: ts, Ev: openEv},
		},
	}

	evt := det.ToDetectionEvent()
	if evt.TechniqueID != "L1002" {
		t.Fatalf("technique_id = %q, want L1002", evt.TechniqueID)
	}
	if evt.Severity != "warn" {
		t.Fatalf("severity = %q, want warn", evt.Severity)
	}
	if evt.PID != 12345 {
		t.Fatalf("pid = %d, want 12345", evt.PID)
	}
	if evt.PPID != 1 {
		t.Fatalf("ppid = %d, want 1", evt.PPID)
	}
	if evt.PWD != "/home/attacker" {
		t.Fatalf("pwd = %q, want /home/attacker", evt.PWD)
	}
	if len(evt.Artifacts) != 1 {
		t.Fatalf("artifacts len = %d, want 1", len(evt.Artifacts))
	}
}
