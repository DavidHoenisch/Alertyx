package integration

import (
	"os"
	"strconv"
	"strings"
)

// KernelRelease returns the running kernel version from /proc/sys/kernel/osrelease.
func KernelRelease() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// KernelMajor returns the major version number of the running kernel, or -1 if unknown.
func KernelMajor() int {
	release := KernelRelease()
	if release == "unknown" {
		return -1
	}
	major, _, ok := strings.Cut(release, ".")
	if !ok {
		return -1
	}
	n, err := strconv.Atoi(major)
	if err != nil {
		return -1
	}
	return n
}
