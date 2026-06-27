package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func techniquesIntegrationTestPath(t *testing.T) string {
	t.Helper()
	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("RepoRoot: %v", err)
	}
	return filepath.Join(root, "test", "integration", "techniques_integration_test.go")
}

func TestTechniquesIntegrationTestFileExists(t *testing.T) {
	path := techniquesIntegrationTestPath(t)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("techniques_integration_test.go not found: %v", err)
	}
}

func TestTechniquesIntegrationTestsCoverL1002L1005T1098(t *testing.T) {
	data, err := os.ReadFile(techniquesIntegrationTestPath(t))
	if err != nil {
		t.Fatalf("read techniques integration tests: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "//go:build integration") {
		t.Fatal("techniques_integration_test.go must use //go:build integration")
	}

	required := []string{
		"TestIntegrationL1005DetectsTmpWrite",
		"TestIntegrationL1002DetectsShadowAccess",
		"TestIntegrationT1098DetectsCrossUserAuthorizedKeysWrite",
		"techs.L1005{}",
		"techs.L1002{}",
		"techs.T1098{}",
		"RunAndWait",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("techniques_integration_test.go must contain %q", marker)
		}
	}
}
