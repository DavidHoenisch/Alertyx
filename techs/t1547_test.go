package techs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidHoenisch/Alertyx/events"
)

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

type t1547HuntFixture struct {
	release        string
	dep            string
	koFiles        map[string][]byte
	autoload       map[string]string
	etcModules     string
	skipModulesDep bool
	skipRelease    bool
	noLoadDir      bool
}

func setupT1547HuntFixture(t *testing.T, cfg t1547HuntFixture) {
	t.Helper()

	root := t.TempDir()
	libModules := filepath.Join(root, "lib", "modules", cfg.release)
	if err := os.MkdirAll(filepath.Join(libModules, "kernel", "drivers"), 0755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if !cfg.skipModulesDep {
		if err := os.WriteFile(filepath.Join(libModules, "modules.dep"), []byte(cfg.dep), 0644); err != nil {
			t.Fatalf("WriteFile(modules.dep) error: %v", err)
		}
	}
	for rel, content := range cfg.koFiles {
		path := filepath.Join(libModules, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("MkdirAll(%q) error: %v", path, err)
		}
		if err := os.WriteFile(path, content, 0644); err != nil {
			t.Fatalf("WriteFile(%q) error: %v", path, err)
		}
	}

	modulesLoadDir := filepath.Join(root, "etc", "modules-load.d")
	if !cfg.noLoadDir {
		if err := os.MkdirAll(modulesLoadDir, 0755); err != nil {
			t.Fatalf("MkdirAll() error: %v", err)
		}
		for name, content := range cfg.autoload {
			path := filepath.Join(modulesLoadDir, name)
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatalf("WriteFile(%q) error: %v", path, err)
			}
		}
	}
	etcModules := filepath.Join(root, "etc", "modules")
	if err := os.MkdirAll(filepath.Dir(etcModules), 0755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(etcModules, []byte(cfg.etcModules), 0644); err != nil {
		t.Fatalf("WriteFile(/etc/modules) error: %v", err)
	}
	releasePath := filepath.Join(root, "proc", "sys", "kernel", "osrelease")
	if !cfg.skipRelease {
		if err := os.MkdirAll(filepath.Dir(releasePath), 0755); err != nil {
			t.Fatalf("MkdirAll() error: %v", err)
		}
		if err := os.WriteFile(releasePath, []byte(cfg.release), 0644); err != nil {
			t.Fatalf("WriteFile(osrelease) error: %v", err)
		}
	}

	oldLib := t1547LibModulesDir
	oldRelease := t1547KernelReleasePath
	oldEtcModules := t1547EtcModulesPath
	oldModulesLoad := t1547ModulesLoadDir
	t1547LibModulesDir = filepath.Join(root, "lib", "modules")
	t1547KernelReleasePath = releasePath
	t1547EtcModulesPath = etcModules
	t1547ModulesLoadDir = modulesLoadDir
	t.Cleanup(func() {
		t1547LibModulesDir = oldLib
		t1547KernelReleasePath = oldRelease
		t1547EtcModulesPath = oldEtcModules
		t1547ModulesLoadDir = oldModulesLoad
	})
}

func TestT1547Hunt(t *testing.T) {
	const release = "6.1.0-test"

	tests := []struct {
		name      string
		fixture   t1547HuntFixture
		wantFound bool
		wantLevel int
		wantErr   bool
	}{
		{
			name: "registered modules only",
			fixture: t1547HuntFixture{
				release: release,
				dep:     "kernel/drivers/foo.ko:\n",
				koFiles: map[string][]byte{
					"kernel/drivers/foo.ko": []byte("ok"),
				},
			},
			wantFound: false,
		},
		{
			name: "unregistered module",
			fixture: t1547HuntFixture{
				release: release,
				dep:     "kernel/drivers/foo.ko:\n",
				koFiles: map[string][]byte{
					"kernel/drivers/foo.ko": []byte("ok"),
					"evil.ko":               []byte("bad"),
				},
			},
			wantFound: true,
			wantLevel: LevelErr,
		},
		{
			name: "autoloaded unregistered module via modules-load.d",
			fixture: t1547HuntFixture{
				release: release,
				dep:     "kernel/drivers/foo.ko:\n",
				koFiles: map[string][]byte{
					"kernel/drivers/foo.ko": []byte("ok"),
					"evil.ko":               []byte("bad"),
				},
				autoload: map[string]string{
					"evil.conf": "evil\n",
				},
			},
			wantFound: true,
			wantLevel: LevelCrit,
		},
		{
			name: "autoloaded unregistered module via etc modules",
			fixture: t1547HuntFixture{
				release: release,
				dep:     "kernel/drivers/foo.ko:\n",
				koFiles: map[string][]byte{
					"kernel/drivers/foo.ko": []byte("ok"),
					"evil.ko":               []byte("bad"),
				},
				etcModules: "# autoload\n evil\n",
			},
			wantFound: true,
			wantLevel: LevelCrit,
		},
		{
			name: "skips build source vdso directories",
			fixture: t1547HuntFixture{
				release: release,
				dep:     "kernel/drivers/foo.ko:\n",
				koFiles: map[string][]byte{
					"kernel/drivers/foo.ko": []byte("ok"),
					"build/evil.ko":         []byte("bad"),
					"source/evil.ko":        []byte("bad"),
					"vdso/evil.ko":          []byte("bad"),
				},
			},
			wantFound: false,
		},
		{
			name: "missing modules dep",
			fixture: t1547HuntFixture{
				release:        release,
				skipModulesDep: true,
			},
			wantErr: true,
		},
		{
			name: "missing kernel release",
			fixture: t1547HuntFixture{
				release:     release,
				dep:         "kernel/drivers/foo.ko:\n",
				skipRelease: true,
			},
			wantErr: true,
		},
		{
			name: "missing modules load dir",
			fixture: t1547HuntFixture{
				release: release,
				dep:     "kernel/drivers/foo.ko:\n",
				koFiles: map[string][]byte{
					"kernel/drivers/foo.ko": []byte("ok"),
					"evil.ko":               []byte("bad"),
				},
				noLoadDir: true,
			},
			wantFound: true,
			wantLevel: LevelErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupT1547HuntFixture(t, tt.fixture)
			got, err := (T1547{}).Hunt()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Hunt() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Hunt() error: %v", err)
			}
			if got.Found != tt.wantFound {
				t.Fatalf("Hunt() Found = %v, want %v", got.Found, tt.wantFound)
			}
			if got.Level != tt.wantLevel {
				t.Fatalf("Hunt() Level = %d, want %d", got.Level, tt.wantLevel)
			}
			if tt.wantFound && got.Ev == nil {
				t.Fatalf("Hunt() Ev = nil, want event with suspicious path")
			}
		})
	}
}

func setupT1547CheckFixture(t *testing.T, modulesDisabled string) {
	t.Helper()

	root := t.TempDir()
	path := filepath.Join(root, "proc", "sys", "kernel", "modules_disabled")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(path, []byte(modulesDisabled), 0644); err != nil {
		t.Fatalf("WriteFile(modules_disabled) error: %v", err)
	}

	old := t1547ModulesDisabledPath
	t1547ModulesDisabledPath = path
	t.Cleanup(func() { t1547ModulesDisabledPath = old })
}

func TestT1547Check(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantFound bool
		wantLevel int
	}{
		{
			name:      "module loading disabled",
			value:     "1\n",
			wantFound: false,
		},
		{
			name:      "module loading allowed",
			value:     "0\n",
			wantFound: true,
			wantLevel: LevelWarn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupT1547CheckFixture(t, tt.value)
			got, err := (T1547{}).Check()
			if err != nil {
				t.Fatalf("Check() error: %v", err)
			}
			if got.Found != tt.wantFound {
				t.Fatalf("Check() Found = %v, want %v", got.Found, tt.wantFound)
			}
			if got.Level != tt.wantLevel {
				t.Fatalf("Check() Level = %d, want %d", got.Level, tt.wantLevel)
			}
		})
	}
}

func TestT1547CheckMissingSysctl(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "proc", "sys", "kernel", "modules_disabled")

	old := t1547ModulesDisabledPath
	t1547ModulesDisabledPath = path
	t.Cleanup(func() { t1547ModulesDisabledPath = old })

	got, err := (T1547{}).Check()
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !got.Found {
		t.Fatal("Check() should report finding when modules_disabled sysctl is absent")
	}
	if got.Level != LevelWarn {
		t.Fatalf("Check() Level = %d, want %d", got.Level, LevelWarn)
	}
}

func TestT1547Mitigate(t *testing.T) {
	tests := []struct {
		name      string
		initial   string
		wantValue string
	}{
		{
			name:      "disables module loading",
			initial:   "0\n",
			wantValue: "1",
		},
		{
			name:      "already disabled is no-op",
			initial:   "1\n",
			wantValue: "1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupT1547CheckFixture(t, tt.initial)
			if err := (T1547{}).Mitigate(); err != nil {
				t.Fatalf("Mitigate() error: %v", err)
			}
			data, err := os.ReadFile(t1547ModulesDisabledPath)
			if err != nil {
				t.Fatalf("ReadFile() error: %v", err)
			}
			if got := strings.TrimSpace(string(data)); got != tt.wantValue {
				t.Fatalf("modules_disabled = %q, want %q", got, tt.wantValue)
			}
		})
	}
}

func TestT1547MitigateMissingSysctl(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "proc", "sys", "kernel", "modules_disabled")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}

	old := t1547ModulesDisabledPath
	t1547ModulesDisabledPath = path
	t.Cleanup(func() { t1547ModulesDisabledPath = old })

	if err := (T1547{}).Mitigate(); err != nil {
		t.Fatalf("Mitigate() error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "1" {
		t.Fatalf("modules_disabled = %q, want %q", got, "1")
	}
}

func TestT1547HelperFunctions(t *testing.T) {
	t.Run("isModuleLoaderExec", func(t *testing.T) {
		tests := []struct {
			argv string
			want bool
		}{
			{"/sbin/insmod evil.ko", true},
			{"modprobe -r foo", true},
			{"/usr/bin/kmod modprobe bar", true},
			{"/bin/ls", false},
			{"rmmod evil", false},
		}
		for _, tt := range tests {
			if got := isModuleLoaderExec(tt.argv); got != tt.want {
				t.Fatalf("isModuleLoaderExec(%q) = %v, want %v", tt.argv, got, tt.want)
			}
		}
	})

	t.Run("modulePersistencePath", func(t *testing.T) {
		tests := []struct {
			filename string
			pwd      string
			want     bool
		}{
			{"/etc/modules", "/", true},
			{"/lib/modules/6.1.0/evil.ko", "/", true},
			{"/etc/modules-load.d/evil.conf", "/", true},
			{"modules", "/etc", true},
			{"evil.conf", "/etc/modules-load.d", true},
			{"evil.ko", "/lib/modules/6.1.0", true},
			{"/etc/passwd", "/", false},
		}
		for _, tt := range tests {
			if got := modulePersistencePath(tt.filename, tt.pwd); got != tt.want {
				t.Fatalf("modulePersistencePath(%q, %q) = %v, want %v", tt.filename, tt.pwd, got, tt.want)
			}
		}
	})

	t.Run("t1547ParseModuleListFile", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "modules.conf")
		content := "# comment\n\nfoo\n bar baz\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}
		got := t1547ParseModuleListFile(path)
		want := []string{"foo", "bar"}
		if len(got) != len(want) {
			t.Fatalf("t1547ParseModuleListFile() = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("t1547ParseModuleListFile()[%d] = %q, want %q", i, got[i], want[i])
			}
		}
		if missing := t1547ParseModuleListFile(filepath.Join(root, "missing")); missing != nil {
			t.Fatalf("t1547ParseModuleListFile(missing) = %v, want nil", missing)
		}
	})
}
