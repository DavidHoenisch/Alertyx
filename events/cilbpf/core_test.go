package cilbpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var coreProgramSources = []string{
	"exec.c",
	"open.c",
	"listen.c",
	"readline.c",
}

func TestCoreProgramSourcesUseCORE(t *testing.T) {
	t.Helper()

	for _, name := range coreProgramSources {
		data, err := os.ReadFile(filepath.Join("src", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(data)
		if strings.Contains(src, "offsets.h") {
			t.Fatalf("%s must not include manual offsets.h", name)
		}
		if !strings.Contains(src, "core_helpers.h") {
			t.Fatalf("%s must include core_helpers.h", name)
		}
	}
}

func TestCoreHelpersUseBPFCoreRead(t *testing.T) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("src", "core_helpers.h"))
	if err != nil {
		t.Fatalf("read core_helpers.h: %v", err)
	}
	src := string(data)
	for _, marker := range []string{"BPF_CORE_READ", "bpf_core_field_exists", "preserve_access_index"} {
		if !strings.Contains(src, marker) && marker != "preserve_access_index" {
			t.Fatalf("core_helpers.h must use %s", marker)
		}
	}

	types, err := os.ReadFile(filepath.Join("src", "core_types.h"))
	if err != nil {
		t.Fatalf("read core_types.h: %v", err)
	}
	if !strings.Contains(string(types), "preserve_access_index") {
		t.Fatal("core_types.h must declare CO-RE struct stubs with preserve_access_index")
	}
}

func bpfTargetArchDefine() string {
	switch runtime.GOARCH {
	case "amd64", "386":
		return "__TARGET_ARCH_x86"
	case "arm64":
		return "__TARGET_ARCH_arm64"
	case "arm":
		return "__TARGET_ARCH_arm"
	case "ppc64le":
		return "__TARGET_ARCH_powerpc"
	case "mips64le", "mipsle":
		return "__TARGET_ARCH_mips"
	case "riscv64":
		return "__TARGET_ARCH_riscv"
	case "s390x":
		return "__TARGET_ARCH_s390"
	default:
		return ""
	}
}

func TestCoreProgramSourcesCompile(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}

	archDefine := bpfTargetArchDefine()
	if archDefine == "" {
		t.Skipf("unsupported GOARCH %s for BPF compile test", runtime.GOARCH)
	}

	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	headers := filepath.Join(root, "headers")
	srcDir := filepath.Join(root, "src")

	for _, name := range coreProgramSources {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Helper()
			out := filepath.Join(t.TempDir(), strings.TrimSuffix(name, ".c")+".o")
			args := []string{
				"-target", "bpf",
				"-O2", "-g",
				"-D" + archDefine,
				"-c", filepath.Join(srcDir, name),
				"-o", out,
				"-I" + headers,
				"-I" + srcDir,
			}
			cmd := exec.Command("clang", args...)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("clang compile %s: %v\n%s", name, err, out)
			}
		})
	}
}
