package docs_test

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

func siemIntegrationDocPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "docs", "siem-integration.md")
}

func readSIEMIntegrationDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(siemIntegrationDocPath(t))
	if err != nil {
		t.Fatalf("failed to read SIEM integration doc: %v", err)
	}
	return string(data)
}

func TestSIEMIntegrationDocExists(t *testing.T) {
	if _, err := os.Stat(siemIntegrationDocPath(t)); err != nil {
		t.Fatalf("docs/siem-integration.md not found: %v", err)
	}
}

func TestSIEMIntegrationDocDocumentsOutputFlag(t *testing.T) {
	content := readSIEMIntegrationDoc(t)
	required := []string{
		"--output json",
		"`text`",
		"`json`",
		"monitor",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("SIEM doc must document %q", marker)
		}
	}
}

func TestSIEMIntegrationDocDocumentsNDJSON(t *testing.T) {
	content := readSIEMIntegrationDoc(t)
	required := []string{
		"NDJSON",
		"newline-delimited JSON",
		"Each detection is a single JSON object on one line",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("SIEM doc must document NDJSON format %q", marker)
		}
	}
}

func TestSIEMIntegrationDocDocumentsEventSchema(t *testing.T) {
	content := readSIEMIntegrationDoc(t)
	fields := []string{
		"timestamp",
		"technique",
		"technique_id",
		"severity",
		"process",
		"pid",
		"ppid",
		"uid",
		"username",
		"pwd",
		"details",
		"artifacts",
	}
	for _, field := range fields {
		if !strings.Contains(content, field) {
			t.Fatalf("SIEM doc must document field %q", field)
		}
	}
}

func TestSIEMIntegrationDocDocumentsSeverityMapping(t *testing.T) {
	content := readSIEMIntegrationDoc(t)
	required := []string{
		"Severity Mapping",
		"crit",
		"err",
		"warn",
		"info",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("SIEM doc must document severity %q", marker)
		}
	}
}

func TestSIEMIntegrationDocDocumentsDeployment(t *testing.T) {
	content := readSIEMIntegrationDoc(t)
	required := []string{
		"Deployment Patterns",
		"Filebeat",
		"Splunk",
		"systemd",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("SIEM doc must document deployment %q", marker)
		}
	}
}

func TestREADMELinksSIEMIntegrationDoc(t *testing.T) {
	readmePath := filepath.Join(repoRoot(t), "README.md")
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "docs/siem-integration.md") {
		t.Fatal("README.md must link to docs/siem-integration.md")
	}
}
