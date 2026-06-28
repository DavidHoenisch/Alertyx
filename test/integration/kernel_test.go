package integration

import (
	"os"
	"testing"
)

func TestKernelReleaseReadableOnLinux(t *testing.T) {
	if _, err := os.Stat("/proc/sys/kernel/osrelease"); err != nil {
		t.Skip("not on Linux with /proc")
	}
	release := KernelRelease()
	if release == "" || release == "unknown" {
		t.Fatalf("KernelRelease() = %q, want non-empty release", release)
	}
}

func TestKernelMajorParsesRelease(t *testing.T) {
	if _, err := os.Stat("/proc/sys/kernel/osrelease"); err != nil {
		t.Skip("not on Linux with /proc")
	}
	major := KernelMajor()
	if major < 4 {
		t.Fatalf("KernelMajor() = %d, want >= 4 on supported kernels", major)
	}
}
