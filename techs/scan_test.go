package techs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/DavidHoenisch/Alertyx/events"
)

func openFlags(flag int) int32 {
	return int32(flag)
}

func TestL1001Scan(t *testing.T) {
	tech := L1001{}

	tests := []struct {
		name  string
		uid   uint32
		found bool
		level int
	}{
		{name: "root uid", uid: 0, found: true, level: LevelWarn},
		{name: "regular user at boundary", uid: 1000, found: true, level: LevelWarn},
		{name: "regular user above boundary", uid: 1001, found: true, level: LevelWarn},
		{name: "service account below boundary", uid: 999, found: false, level: LevelNil},
		{name: "service account mid range", uid: 500, found: false, level: LevelNil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := events.NewListen(tt.uid, 42)
			got := tech.Scan(ev)
			if got.Found != tt.found {
				t.Fatalf("Scan() Found = %v, want %v", got.Found, tt.found)
			}
			if got.Level != tt.level {
				t.Fatalf("Scan() Level = %v, want %v", got.Level, tt.level)
			}
		})
	}
}

func TestL1002Scan(t *testing.T) {
	tech := L1002{}

	t.Run("non open event ignored", func(t *testing.T) {
		ev := events.NewListen(1000, 7001)
		got := tech.Scan(ev)
		if got.Found {
			t.Fatal("expected non-open event to be ignored")
		}
	})

	t.Run("open on unrelated file ignored", func(t *testing.T) {
		ev := events.NewOpen(1000, 7002, "/etc/passwd", openFlags(os.O_RDONLY), "/", 0)
		got := tech.Scan(ev)
		if got.Found {
			t.Fatal("expected unrelated open to be ignored")
		}
	})

	t.Run("shadow access without exec correlation ignored", func(t *testing.T) {
		ev := events.NewOpen(1000, 7003, "/etc/shadow", openFlags(os.O_RDONLY), "/", 0)
		got := tech.Scan(ev)
		if got.Found {
			t.Fatal("expected missing exec correlation to skip detection")
		}
	})

	t.Run("shadow access from sudo permitted", func(t *testing.T) {
		pid := uint32(7004)
		events.Log(events.NewExec(1000, pid, "/usr/bin/sudo -i"))
		ev := events.NewOpen(1000, pid, "/etc/shadow", openFlags(os.O_RDONLY), "/", 0)
		got := tech.Scan(ev)
		if got.Found {
			t.Fatal("expected sudo access to /etc/shadow to be permitted")
		}
	})

	t.Run("shadow access from unexpected binary flagged", func(t *testing.T) {
		pid := uint32(7005)
		events.Log(events.NewExec(1000, pid, "/usr/bin/cat /etc/shadow"))
		ev := events.NewOpen(1000, pid, "/etc/shadow", openFlags(os.O_RDONLY), "/", 0)
		got := tech.Scan(ev)
		if !got.Found {
			t.Fatal("expected suspicious /etc/shadow access to be flagged")
		}
		if got.Level != LevelWarn {
			t.Fatalf("Scan() Level = %v, want %v", got.Level, LevelWarn)
		}
	})
}

func TestL1003Scan(t *testing.T) {
	tech := L1003{}

	t.Run("non open event ignored", func(t *testing.T) {
		ev := events.NewListen(1000, 7101)
		got := tech.Scan(ev)
		if got.Found {
			t.Fatal("expected non-open event to be ignored")
		}
	})

	t.Run("shadow access from unexpected binary flagged", func(t *testing.T) {
		pid := uint32(7102)
		events.Log(events.NewExec(1000, pid, "/usr/bin/nano"))
		ev := events.NewOpen(1000, pid, "/etc/shadow", openFlags(os.O_RDONLY), "/", 0)
		got := tech.Scan(ev)
		if !got.Found {
			t.Fatal("expected suspicious /etc/shadow access to be flagged")
		}
		if got.Level != LevelWarn {
			t.Fatalf("Scan() Level = %v, want %v", got.Level, LevelWarn)
		}
	})

	t.Run("shadow access from su permitted", func(t *testing.T) {
		pid := uint32(7103)
		events.Log(events.NewExec(1000, pid, "/usr/bin/su root"))
		ev := events.NewOpen(1000, pid, "/etc/shadow", openFlags(os.O_RDONLY), "/", 0)
		got := tech.Scan(ev)
		if got.Found {
			t.Fatal("expected su access to /etc/shadow to be permitted")
		}
	})
}

func TestL1004Scan(t *testing.T) {
	tech := L1004{}

	tests := []struct {
		name     string
		filename string
		pwd      string
		flags    int32
		found    bool
		level    int
	}{
		{
			name:     "read only etc file ignored",
			filename: "/etc/hosts",
			flags:    openFlags(os.O_RDONLY),
			found:    false,
			level:    LevelNil,
		},
		{
			name:     "write etc file by path flagged",
			filename: "/etc/hosts",
			flags:    openFlags(os.O_WRONLY),
			found:    true,
			level:    LevelErr,
		},
		{
			name:     "write etc file by pwd flagged",
			filename: "hosts",
			pwd:      "/etc",
			flags:    openFlags(os.O_RDWR),
			found:    true,
			level:    LevelErr,
		},
		{
			name:     "write outside etc ignored",
			filename: "/tmp/hosts",
			flags:    openFlags(os.O_WRONLY),
			found:    false,
			level:    LevelNil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := events.NewOpen(1000, 7201, tt.filename, tt.flags, tt.pwd, 0)
			got := tech.Scan(ev)
			if got.Found != tt.found {
				t.Fatalf("Scan() Found = %v, want %v", got.Found, tt.found)
			}
			if got.Level != tt.level {
				t.Fatalf("Scan() Level = %v, want %v", got.Level, tt.level)
			}
		})
	}
}

func TestL1005Scan(t *testing.T) {
	tech := L1005{}

	tests := []struct {
		name     string
		filename string
		pwd      string
		flags    int32
		found    bool
		level    int
	}{
		{
			name:     "read only tmp file ignored",
			filename: "/tmp/data",
			flags:    openFlags(os.O_RDONLY),
			found:    false,
			level:    LevelNil,
		},
		{
			name:     "write tmp file flagged warn",
			filename: "/tmp/data",
			flags:    openFlags(os.O_WRONLY),
			found:    true,
			level:    LevelWarn,
		},
		{
			name:     "write tmp file by pwd flagged warn",
			filename: "data",
			pwd:      "/tmp",
			flags:    openFlags(os.O_RDWR),
			found:    true,
			level:    LevelWarn,
		},
		{
			name:     "write dev shm flagged critical",
			filename: "/dev/shm/payload",
			flags:    openFlags(os.O_CREATE),
			found:    true,
			level:    LevelErr,
		},
		{
			name:     "write dev shm by pwd flagged critical",
			filename: "payload",
			pwd:      "/dev/shm",
			flags:    openFlags(os.O_WRONLY),
			found:    true,
			level:    LevelErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := events.NewOpen(1000, 7301, tt.filename, tt.flags, tt.pwd, 0)
			got := tech.Scan(ev)
			if got.Found != tt.found {
				t.Fatalf("Scan() Found = %v, want %v", got.Found, tt.found)
			}
			if got.Level != tt.level {
				t.Fatalf("Scan() Level = %v, want %v", got.Level, tt.level)
			}
		})
	}
}

func TestT1098Scan(t *testing.T) {
	tech := T1098{}

	t.Run("non open event ignored", func(t *testing.T) {
		ev := events.NewListen(1000, 7401)
		got := tech.Scan(ev)
		if got.Found {
			t.Fatal("expected non-open event to be ignored")
		}
	})

	t.Run("read authorized keys ignored", func(t *testing.T) {
		ev := events.NewOpen(1000, 7402, "/home/user/.ssh/authorized_keys", openFlags(os.O_RDONLY), "/home/user/.ssh", 3)
		got := tech.Scan(ev)
		if got.Found {
			t.Fatal("expected read-only authorized_keys access to be ignored")
		}
	})

	t.Run("failed write flagged warn", func(t *testing.T) {
		ev := events.NewOpen(1000, 7403, "/home/user/.ssh/authorized_keys", openFlags(os.O_WRONLY), "/home/user/.ssh", -1)
		got := tech.Scan(ev)
		if !got.Found {
			t.Fatal("expected failed authorized_keys write to be flagged")
		}
		if got.Level != LevelWarn {
			t.Fatalf("Scan() Level = %v, want %v", got.Level, LevelWarn)
		}
	})

	t.Run("missing file flagged critical", func(t *testing.T) {
		ev := events.NewOpen(1000, 7404, "/no/such/authorized_keys", openFlags(os.O_WRONLY), "/", 3)
		got := tech.Scan(ev)
		if !got.Found {
			t.Fatal("expected missing authorized_keys target to be flagged")
		}
		if got.Level != LevelCrit {
			t.Fatalf("Scan() Level = %v, want %v", got.Level, LevelCrit)
		}
	})

	t.Run("owner mismatch flagged critical", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "authorized_keys")
		if err := os.WriteFile(path, []byte("ssh-rsa AAA"), 0600); err != nil {
			t.Fatalf("write temp authorized_keys: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat temp authorized_keys: %v", err)
		}
		ownerUID := info.Sys().(*syscall.Stat_t).Uid
		ev := events.NewOpen(ownerUID+1, 7405, path, openFlags(os.O_WRONLY), dir, 3)
		got := tech.Scan(ev)
		if !got.Found {
			t.Fatal("expected owner mismatch on authorized_keys to be flagged")
		}
		if got.Level != LevelCrit {
			t.Fatalf("Scan() Level = %v, want %v", got.Level, LevelCrit)
		}
	})

	t.Run("matching owner write ignored", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "authorized_keys")
		if err := os.WriteFile(path, []byte("ssh-rsa AAA"), 0600); err != nil {
			t.Fatalf("write temp authorized_keys: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat temp authorized_keys: %v", err)
		}
		ownerUID := info.Sys().(*syscall.Stat_t).Uid
		ev := events.NewOpen(uint32(ownerUID), 7406, path, openFlags(os.O_WRONLY), dir, 3)
		got := tech.Scan(ev)
		if got.Found {
			t.Fatal("expected matching owner authorized_keys write to be ignored")
		}
	})

	t.Run("unrelated file ignored", func(t *testing.T) {
		ev := events.NewOpen(1000, 7407, "/home/user/.ssh/id_rsa", openFlags(os.O_WRONLY), "/home/user/.ssh", 3)
		got := tech.Scan(ev)
		if got.Found {
			t.Fatal("expected unrelated ssh file to be ignored")
		}
	})
}

func TestT1547Scan(t *testing.T) {
	tech := T1547{}
	got := tech.Scan(events.NewOpen(1000, 7501, "/etc/modprobe.d/evil.conf", openFlags(os.O_WRONLY), "/etc/modprobe.d", 0))
	if got.Found {
		t.Fatal("expected T1547 placeholder scan to ignore events")
	}
}

func TestAllRegistersEveryTechnique(t *testing.T) {
	all := All()
	if len(all) != 7 {
		t.Fatalf("All() returned %d techniques, want 7", len(all))
	}
	names := map[string]struct{}{}
	for _, tech := range all {
		names[tech.Name()] = struct{}{}
	}
	for _, want := range []string{
		"Listen from Non-Service account",
		"Suspicious /etc/shadow Access",
		"eBPF Module Persistence",
		"File Modified in /etc/",
		"File Modification in Temporary Filesystem",
		"SSH Authorized Keys Manipulation",
		"Kernel Modules Persistence",
	} {
		if _, ok := names[want]; !ok {
			t.Fatalf("All() missing technique %q", want)
		}
	}
}
