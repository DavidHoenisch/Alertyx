package analysis

import (
	"strings"
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
	openEv.Flags = 0
	copyCString(openEv.Pwd[:], "/home/attacker")
	copyCString(openEv.Filename[:], "/etc/shadow")

	execEv := &events.Exec{}
	execEv.Pid = 12345
	copyCString(execEv.Comm[:], "cat")
	copyCString(execEv.Argv[:], "/bin/cat")

	det := &Detection{
		Time:  ts,
		Level: techs.LevelWarn,
		Tech:  techs.L1002{},
		Artifacts: []events.LogItem{
			{Time: ts, Ev: openEv},
			{Time: ts, Ev: execEv},
		},
	}

	evt := det.ToDetectionEvent()
	if !evt.Timestamp.Equal(ts) {
		t.Fatalf("timestamp = %v, want %v", evt.Timestamp, ts)
	}
	if evt.Technique != "Suspicious /etc/shadow Access" {
		t.Fatalf("technique = %q, want Suspicious /etc/shadow Access", evt.Technique)
	}
	if evt.TechniqueID != "L1002" {
		t.Fatalf("technique_id = %q, want L1002", evt.TechniqueID)
	}
	if evt.Severity != "warn" {
		t.Fatalf("severity = %q, want warn", evt.Severity)
	}
	if evt.Process != "cat" {
		t.Fatalf("process = %q, want cat", evt.Process)
	}
	if evt.PID != 12345 {
		t.Fatalf("pid = %d, want 12345", evt.PID)
	}
	if evt.PPID != 1 {
		t.Fatalf("ppid = %d, want 1", evt.PPID)
	}
	if evt.UID != 0 {
		t.Fatalf("uid = %d, want 0", evt.UID)
	}
	if evt.Username != "root" {
		t.Fatalf("username = %q, want root", evt.Username)
	}
	if evt.PWD != "/home/attacker" {
		t.Fatalf("pwd = %q, want /home/attacker", evt.PWD)
	}
	if !strings.Contains(evt.Details, "/etc/shadow") {
		t.Fatalf("details = %q, want primary artifact event description", evt.Details)
	}
	if !strings.Contains(evt.Details, "/home/attacker") {
		t.Fatalf("details = %q, want pwd in artifact description", evt.Details)
	}
	if len(evt.Artifacts) != 2 {
		t.Fatalf("artifacts len = %d, want 2", len(evt.Artifacts))
	}
}

func TestDetectionToDetectionEventExecProcess(t *testing.T) {
	execEv := &events.Exec{}
	execEv.Pid = 4242
	execEv.Ppid = 1
	execEv.Uid = 0
	copyCString(execEv.Comm[:], "curl")
	copyCString(execEv.Pwd[:], "/tmp")
	copyCString(execEv.Argv[:], "/usr/bin/curl")

	det := &Detection{
		Time:  time.Now(),
		Level: techs.LevelErr,
		Tech:  techs.L1001{},
		Artifacts: []events.LogItem{
			{Ev: execEv},
		},
	}

	evt := det.ToDetectionEvent()
	if evt.Process != "curl" {
		t.Fatalf("process = %q, want curl", evt.Process)
	}
	if evt.PID != 4242 {
		t.Fatalf("pid = %d, want 4242", evt.PID)
	}
	if evt.Severity != "err" {
		t.Fatalf("severity = %q, want err", evt.Severity)
	}
}

func TestDetectionDetailsWithoutArtifacts(t *testing.T) {
	det := &Detection{
		Time:  time.Now(),
		Level: techs.LevelWarn,
		Tech:  techs.L1002{},
	}

	evt := det.ToDetectionEvent()
	if evt.Details != det.Brief() {
		t.Fatalf("details = %q, want Brief() fallback %q", evt.Details, det.Brief())
	}
	if evt.Process != "" {
		t.Fatalf("process = %q, want empty without artifacts", evt.Process)
	}
}
