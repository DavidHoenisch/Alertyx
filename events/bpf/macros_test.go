package bpf

import (
	"strings"
	"testing"
)

func TestGatherStrEnablesPPIDTracking(t *testing.T) {
	t.Helper()

	if strings.Contains(gatherStr, "ppid = 0") {
		t.Fatal("gatherStr must not disable PPID with ppid = 0")
	}
	if !strings.Contains(gatherStr, "real_parent") {
		t.Fatal("gatherStr must read parent task from real_parent")
	}
	if !strings.Contains(gatherStr, "bpf_probe_read(&event.ppid") {
		t.Fatal("gatherStr must populate ppid via bpf_probe_read for kernel compatibility")
	}
}

func TestGatherStrSetsUID(t *testing.T) {
	t.Helper()

	if !strings.Contains(gatherStr, "bpf_get_current_uid_gid()") {
		t.Fatal("gatherStr must set event.uid from bpf_get_current_uid_gid()")
	}
	if !strings.Contains(gatherStr, "event.uid = uid_gid") {
		t.Fatal("gatherStr must assign uid_gid to event.uid")
	}
}

func TestGatherStrSetsPID(t *testing.T) {
	t.Helper()

	if !strings.Contains(gatherStr, "bpf_get_current_pid_tgid()") {
		t.Fatal("gatherStr must set event.pid from bpf_get_current_pid_tgid()")
	}
}

func TestEventBaseStrIncludesPPIDField(t *testing.T) {
	t.Helper()

	if !strings.Contains(eventBaseStr, "u32 ppid") {
		t.Fatal("eventBaseStr must declare ppid field for userspace correlation")
	}
}
