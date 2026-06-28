package deploy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	return filepath.Join(filepath.Dir(filename), "..")
}

func servicePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "deploy", "alertyx.service")
}

func readService(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(servicePath(t))
	if err != nil {
		t.Fatalf("failed to read service file: %v", err)
	}
	return string(data)
}

func section(content, name string) string {
	start := strings.Index(content, "["+name+"]")
	if start == -1 {
		return ""
	}
	start += len("["+name+"]") + 1
	end := strings.Index(content[start:], "\n[")
	if end == -1 {
		return content[start:]
	}
	return content[start : start+end]
}

func TestServiceFileExists(t *testing.T) {
	if _, err := os.Stat(servicePath(t)); err != nil {
		t.Fatalf("service file not found: %v", err)
	}
}

func TestServiceFileHasRequiredSections(t *testing.T) {
	content := readService(t)
	for _, sectionName := range []string{"Unit", "Service", "Install"} {
		if !strings.Contains(content, "["+sectionName+"]") {
			t.Fatalf("service file missing [%s] section", sectionName)
		}
	}
}

func TestServiceUnitSection(t *testing.T) {
	unit := section(readService(t), "Unit")
	required := []string{
		"Description=Alertyx eBPF-based Linux EDR",
		"Documentation=https://github.com/DavidHoenisch/Alertyx",
		"After=network.target",
	}
	for _, line := range required {
		if !strings.Contains(unit, line) {
			t.Fatalf("Unit section missing %q", line)
		}
	}
}

func TestServiceExecStartUsesMonitorWithSyslog(t *testing.T) {
	service := section(readService(t), "Service")
	if !strings.Contains(service, "ExecStart=/usr/local/bin/alertyx monitor --syslog") {
		t.Fatal("Service section must run monitor with --syslog for journal integration")
	}
}

func TestServiceRestartPolicy(t *testing.T) {
	service := section(readService(t), "Service")
	for _, line := range []string{"Type=simple", "Restart=always", "RestartSec=5"} {
		if !strings.Contains(service, line) {
			t.Fatalf("Service section missing %q", line)
		}
	}
}

func TestServiceCapabilityRequirements(t *testing.T) {
	service := section(readService(t), "Service")
	if !strings.Contains(service, "NoNewPrivileges=no") {
		t.Fatal("BPF workloads require NoNewPrivileges=no")
	}

	caps := "CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE"
	for _, key := range []string{"CapabilityBoundingSet=", "AmbientCapabilities="} {
		if !strings.Contains(service, key+caps) {
			t.Fatalf("Service section missing %s%s", key, caps)
		}
	}
}

func TestServiceResourceLimits(t *testing.T) {
	service := section(readService(t), "Service")
	for _, line := range []string{"MemoryMax=512M", "CPUQuota=50%"} {
		if !strings.Contains(service, line) {
			t.Fatalf("Service section missing %q", line)
		}
	}
}

func TestServiceLoggingConfiguration(t *testing.T) {
	service := section(readService(t), "Service")
	for _, line := range []string{
		"StandardOutput=journal",
		"StandardError=journal",
		"SyslogIdentifier=alertyx",
	} {
		if !strings.Contains(service, line) {
			t.Fatalf("Service section missing %q", line)
		}
	}
}

func TestServiceInstallTarget(t *testing.T) {
	install := section(readService(t), "Install")
	if !strings.Contains(install, "WantedBy=multi-user.target") {
		t.Fatal("Install section must target multi-user.target")
	}
}
