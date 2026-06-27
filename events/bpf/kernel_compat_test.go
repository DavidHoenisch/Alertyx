package bpf

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSupportedKernelMajorsInclude567(t *testing.T) {
	t.Helper()

	want := map[int]bool{5: false, 6: false, 7: false}
	for _, major := range SupportedKernelMajors {
		if _, ok := want[major]; ok {
			want[major] = true
		}
	}
	for major, found := range want {
		if !found {
			t.Fatalf("SupportedKernelMajors must include kernel %d.x", major)
		}
	}
}

func TestGatherStrCompatibleWithKernel567(t *testing.T) {
	t.Helper()

	if err := ValidatePPIDGatherCompat(gatherStr); err != nil {
		t.Fatalf("gatherStr must be compatible with kernels 5.x–7.x: %v", err)
	}
}

func TestAllBPFSourcesEmbedGatherStr(t *testing.T) {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	dir := filepath.Dir(filename)

	sources := []string{
		"exec_bpf.go",
		"open_bpf.go",
		"listen_bpf.go",
		"readline_bpf.go",
	}
	for _, name := range sources {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		content := string(data)
		if !strings.Contains(content, "gatherStr") {
			t.Fatalf("%s must embed gatherStr for PPID tracking", name)
		}
	}
}
