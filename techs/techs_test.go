package techs

import (
	"container/ring"
	"os"
	"syscall"
	"testing"

	"github.com/DavidHoenisch/Alertyx/events"
)

func copyCString(dst []byte, s string) {
	copy(dst, s)
	if len(s) < len(dst) {
		dst[len(s)] = 0
	}
}

func resetEventLog(t *testing.T) {
	t.Helper()
	original := events.EventLog
	t.Cleanup(func() { events.EventLog = original })
	events.EventLog = ring.New(100)
}

func openEvent(uid, pid uint32, filename string, flags int, pwd string, retVal int32) *events.Open {
	ev := &events.Open{Flags: int32(flags)}
	ev.Uid = uid
	ev.Pid = pid
	ev.RetVal = retVal
	copyCString(ev.Filename[:], filename)
	copyCString(ev.Pwd[:], pwd)
	return ev
}

func execEvent(uid, pid uint32, argv string) *events.Exec {
	ev := &events.Exec{}
	ev.Uid = uid
	ev.Pid = pid
	copyCString(ev.Argv[:], argv)
	return ev
}

func listenEvent(uid, pid uint32) *events.Listen {
	ev := &events.Listen{}
	ev.Uid = uid
	ev.Pid = pid
	return ev
}

func TestAllReturnsEveryTechnique(t *testing.T) {
	all := All()
	if len(all) != 7 {
		t.Fatalf("All() len = %d, want 7", len(all))
	}

	wantNames := map[string]bool{
		"Listen from Non-Service account":      false,
		"Suspicious /etc/shadow Access":      false,
		"eBPF Module Persistence":            false,
		"File Modified in /etc/":             false,
		"File Modification in Temporary Filesystem": false,
		"SSH Authorized Keys Manipulation":   false,
		"Kernel Modules Persistence":         false,
	}
	for _, tech := range all {
		name := tech.Name()
		if _, ok := wantNames[name]; !ok {
			t.Fatalf("unexpected technique name %q", name)
		}
		wantNames[name] = true
	}
	for name, seen := range wantNames {
		if !seen {
			t.Fatalf("All() missing technique %q", name)
		}
	}
}

func TestTechBaseDefaults(t *testing.T) {
	base := techBase{}
	finding, err := base.Hunt()
	if err != nil || finding.Found {
		t.Fatalf("Hunt() = %+v, %v; want empty finding", finding, err)
	}
	if err := base.Clean(&events.Open{}); err != nil {
		t.Fatalf("Clean() error: %v", err)
	}
	finding, err = base.Check()
	if err != nil || finding.Found {
		t.Fatalf("Check() = %+v, %v; want empty finding", finding, err)
	}
	if err := base.Mitigate(); err != nil {
		t.Fatalf("Mitigate() error: %v", err)
	}
}

func TestL1001Name(t *testing.T) {
	if got := (L1001{}).Name(); got != "Listen from Non-Service account" {
		t.Fatalf("Name() = %q", got)
	}
}

func TestL1001Scan(t *testing.T) {
	tests := []struct {
		name  string
		uid   uint32
		found bool
		level int
	}{
		{"root uid", 0, true, LevelWarn},
		{"regular user", 1000, true, LevelWarn},
		{"service account", 500, false, LevelNil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := listenEvent(tt.uid, 1234)
			got := L1001{}.Scan(ev)
			if got.Found != tt.found {
				t.Fatalf("Scan() Found = %v, want %v", got.Found, tt.found)
			}
			if got.Level != tt.level {
				t.Fatalf("Scan() Level = %d, want %d", got.Level, tt.level)
			}
		})
	}
}

func TestL1001CleanNoListenEvents(t *testing.T) {
	resetEventLog(t)
	ev := openEvent(1000, 1, "/tmp/x", os.O_WRONLY, "/tmp", 0)
	err := L1001{}.Clean(ev)
	if err == nil {
		t.Fatal("Clean() expected error when no listen events exist")
	}
}

func TestL1001CleanKillsListenProcess(t *testing.T) {
	resetEventLog(t)
	uid := uint32(1000)
	pid := uint32(999999)
	events.Log(listenEvent(uid, pid))
	ev := openEvent(uid, 1, "/tmp/x", os.O_WRONLY, "/tmp", 0)
	_ = L1001{}.Clean(ev)
}

func TestL1002Name(t *testing.T) {
	if got := (L1002{}).Name(); got != "Suspicious /etc/shadow Access" {
		t.Fatalf("Name() = %q", got)
	}
}

func TestL1002Scan(t *testing.T) {
	tests := []struct {
		name    string
		setup   func()
		ev      events.Event
		found   bool
		level   int
	}{
		{
			name:  "non-open event",
			ev:    listenEvent(1000, 1),
			found: false,
		},
		{
			name:  "unrelated open",
			ev:    openEvent(1000, 1, "/etc/passwd", os.O_RDONLY, "/", 0),
			found: false,
		},
		{
			name: "shadow open without exec history",
			setup: func() {
				resetEventLog(t)
			},
			ev:    openEvent(1000, 42, "/etc/shadow", os.O_RDONLY, "/", 0),
			found: false,
		},
		{
			name: "shadow open from sudo",
			setup: func() {
				resetEventLog(t)
				events.Log(execEvent(1000, 42, "/usr/bin/sudo cat /etc/shadow"))
			},
			ev:    openEvent(1000, 42, "/etc/shadow", os.O_RDONLY, "/", 0),
			found: false,
		},
		{
			name: "shadow open from suspicious binary",
			setup: func() {
				resetEventLog(t)
				events.Log(execEvent(1000, 42, "/usr/bin/cat /etc/shadow"))
			},
			ev:    openEvent(1000, 42, "/etc/shadow", os.O_RDONLY, "/", 0),
			found: true,
			level: LevelWarn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			got := L1002{}.Scan(tt.ev)
			if got.Found != tt.found {
				t.Fatalf("Scan() Found = %v, want %v", got.Found, tt.found)
			}
			if got.Level != tt.level {
				t.Fatalf("Scan() Level = %d, want %d", got.Level, tt.level)
			}
		})
	}
}

func TestL1002Check(t *testing.T) {
	finding, err := L1002{}.Check()
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !finding.Found {
		t.Fatal("Check() should report finding")
	}
}

func TestL1003Name(t *testing.T) {
	if got := (L1003{}).Name(); got != "eBPF Module Persistence" {
		t.Fatalf("Name() = %q", got)
	}
}

func TestL1003Scan(t *testing.T) {
	resetEventLog(t)
	events.Log(execEvent(1000, 55, "/bin/evil"))
	ev := openEvent(1000, 55, "/etc/shadow", os.O_RDONLY, "/", 0)
	got := L1003{}.Scan(ev)
	if !got.Found || got.Level != LevelWarn {
		t.Fatalf("Scan() = %+v, want suspicious shadow access", got)
	}
}

func TestL1004Name(t *testing.T) {
	if got := (L1004{}).Name(); got != "File Modified in /etc/" {
		t.Fatalf("Name() = %q", got)
	}
}

func TestL1004Scan(t *testing.T) {
	tests := []struct {
		name  string
		ev    *events.Open
		found bool
		level int
	}{
		{
			name:  "read only etc file",
			ev:    openEvent(0, 1, "/etc/passwd", os.O_RDONLY, "/", 0),
			found: false,
		},
		{
			name:  "write etc file by path",
			ev:    openEvent(0, 1, "/etc/hosts", os.O_WRONLY, "/tmp", 0),
			found: true,
			level: LevelErr,
		},
		{
			name:  "write etc file by pwd",
			ev:    openEvent(0, 1, "hosts", os.O_RDWR, "/etc", 0),
			found: true,
			level: LevelErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := L1004{}.Scan(tt.ev)
			if got.Found != tt.found {
				t.Fatalf("Scan() Found = %v, want %v", got.Found, tt.found)
			}
			if got.Level != tt.level {
				t.Fatalf("Scan() Level = %d, want %d", got.Level, tt.level)
			}
		})
	}
}

func TestL1005Name(t *testing.T) {
	if got := (L1005{}).Name(); got != "File Modification in Temporary Filesystem" {
		t.Fatalf("Name() = %q", got)
	}
}

func TestL1005Scan(t *testing.T) {
	tests := []struct {
		name  string
		ev    *events.Open
		found bool
		level int
	}{
		{
			name:  "read tmp file",
			ev:    openEvent(0, 1, "/tmp/read.txt", os.O_RDONLY, "/tmp", 0),
			found: false,
		},
		{
			name:  "write tmp file",
			ev:    openEvent(0, 1, "/tmp/write.txt", os.O_WRONLY, "/home", 0),
			found: true,
			level: LevelWarn,
		},
		{
			name:  "write tmp file by pwd",
			ev:    openEvent(0, 1, "payload", os.O_WRONLY, "/var/tmp", 0),
			found: true,
			level: LevelWarn,
		},
		{
			name:  "write dev shm",
			ev:    openEvent(0, 1, "/dev/shm/malware", os.O_WRONLY, "/", 0),
			found: true,
			level: LevelErr,
		},
		{
			name:  "write shm by pwd",
			ev:    openEvent(0, 1, "malware", os.O_WRONLY, "/dev/shm", 0),
			found: true,
			level: LevelErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := L1005{}.Scan(tt.ev)
			if got.Found != tt.found {
				t.Fatalf("Scan() Found = %v, want %v", got.Found, tt.found)
			}
			if got.Level != tt.level {
				t.Fatalf("Scan() Level = %d, want %d", got.Level, tt.level)
			}
		})
	}
}

func TestT1098Name(t *testing.T) {
	if got := (T1098{}).Name(); got != "SSH Authorized Keys Manipulation" {
		t.Fatalf("Name() = %q", got)
	}
}

func shortAuthorizedKeysPath(t *testing.T) string {
	t.Helper()
	path := "/tmp/authorized_keys_test"
	if err := os.WriteFile(path, []byte("ssh-rsa AAA"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func TestT1098Scan(t *testing.T) {
	t.Run("read authorized_keys", func(t *testing.T) {
		ev := openEvent(1000, 1, "/home/user/.ssh/authorized_keys", os.O_RDONLY, "/home/user/.ssh", 0)
		got := T1098{}.Scan(ev)
		if got.Found {
			t.Fatalf("Scan() = %+v, want no finding for read-only access", got)
		}
	})

	t.Run("failed write authorized_keys", func(t *testing.T) {
		ev := openEvent(1000, 1, "/home/user/.ssh/authorized_keys", os.O_WRONLY, "/home/user/.ssh", -1)
		got := T1098{}.Scan(ev)
		if !got.Found || got.Level != LevelWarn {
			t.Fatalf("Scan() = %+v, want warn on failed write", got)
		}
	})

	t.Run("write authorized_keys owner stat error", func(t *testing.T) {
		ev := openEvent(1000, 1, "/no/such/path/authorized_keys", os.O_WRONLY, "/", 0)
		got := T1098{}.Scan(ev)
		if !got.Found || got.Level != LevelCrit {
			t.Fatalf("Scan() = %+v, want critical on owner lookup failure", got)
		}
	})

	t.Run("write authorized_keys owner mismatch", func(t *testing.T) {
		path := shortAuthorizedKeysPath(t)
		ev := openEvent(99999, 1, path, os.O_WRONLY, "/tmp", 0)
		got := T1098{}.Scan(ev)
		if !got.Found || got.Level != LevelCrit {
			t.Fatalf("Scan() = %+v, want critical on owner mismatch", got)
		}
	})

	t.Run("write authorized_keys matching owner", func(t *testing.T) {
		path := shortAuthorizedKeysPath(t)
		statUID := fileOwnerUID(t, path)
		ev := openEvent(statUID, 1, path, os.O_WRONLY, "/tmp", 0)
		got := T1098{}.Scan(ev)
		if got.Found {
			t.Fatalf("Scan() = %+v, want no finding when uid matches owner", got)
		}
	})
}

func fileOwnerUID(t *testing.T, path string) uint32 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	return uint32(info.Sys().(*syscall.Stat_t).Uid)
}

func TestT1098CheckAndMitigate(t *testing.T) {
	finding, err := T1098{}.Check()
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if finding.Found {
		t.Fatal("Check() should return empty finding")
	}
	if err := (T1098{}).Mitigate(); err != nil {
		t.Fatalf("Mitigate() error: %v", err)
	}
}

func TestT1547Name(t *testing.T) {
	if got := (T1547{}).Name(); got != "Kernel Modules Persistence" {
		t.Fatalf("Name() = %q", got)
	}
}

func TestT1547Scan(t *testing.T) {
	tests := []struct {
		name  string
		ev    events.Event
		found bool
		level int
	}{
		{
			name:  "read etc modules",
			ev:    openEvent(0, 1, "/etc/modules", os.O_RDONLY, "/", 0),
			found: false,
		},
		{
			name:  "write etc modules",
			ev:    openEvent(0, 1, "/etc/modules", os.O_WRONLY, "/", 0),
			found: true,
			level: LevelErr,
		},
		{
			name:  "write etc modules by pwd",
			ev:    openEvent(0, 1, "modules", os.O_WRONLY, "/etc", 0),
			found: true,
			level: LevelErr,
		},
		{
			name:  "write modules load drop-in",
			ev:    openEvent(0, 1, "/etc/modules-load.d/evil.conf", os.O_WRONLY, "/", 0),
			found: true,
			level: LevelErr,
		},
		{
			name:  "write modules load drop-in by pwd",
			ev:    openEvent(0, 1, "evil.conf", os.O_WRONLY, "/etc/modules-load.d", 0),
			found: true,
			level: LevelErr,
		},
		{
			name:  "write lib modules tree",
			ev:    openEvent(0, 1, "/lib/modules/6.1.0/evil.ko", os.O_WRONLY, "/", 0),
			found: true,
			level: LevelErr,
		},
		{
			name:  "write lib modules tree by pwd",
			ev:    openEvent(0, 1, "evil.ko", os.O_WRONLY, "/lib/modules/6.1.0", 0),
			found: true,
			level: LevelErr,
		},
		{
			name:  "unrelated open",
			ev:    openEvent(0, 1, "/etc/passwd", os.O_WRONLY, "/", 0),
			found: false,
		},
		{
			name:  "insmod exec",
			ev:    execEvent(0, 1, "/sbin/insmod /tmp/evil.ko"),
			found: true,
			level: LevelWarn,
		},
		{
			name:  "modprobe exec",
			ev:    execEvent(0, 1, "/sbin/modprobe evil"),
			found: true,
			level: LevelWarn,
		},
		{
			name:  "unrelated exec",
			ev:    execEvent(0, 1, "/bin/ls /tmp"),
			found: false,
		},
		{
			name:  "listen event",
			ev:    listenEvent(0, 1),
			found: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := T1547{}.Scan(tt.ev)
			if got.Found != tt.found {
				t.Fatalf("Scan() Found = %v, want %v", got.Found, tt.found)
			}
			if got.Level != tt.level {
				t.Fatalf("Scan() Level = %d, want %d", got.Level, tt.level)
			}
		})
	}
}

func TestFindingStruct(t *testing.T) {
	ev := openEvent(1000, 1, "/tmp/x", os.O_WRONLY, "/tmp", 0)
	f := Finding{Ev: ev, Found: true, Level: LevelErr}
	if !f.Found || f.Level != LevelErr || f.Ev == nil {
		t.Fatalf("Finding = %+v", f)
	}
}
