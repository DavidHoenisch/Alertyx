package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gremlinsConfigPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), ".gremlins.yaml")
}

func mutationTestScriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "scripts", "mutation-test.sh")
}

func readGremlinsConfig(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(gremlinsConfigPath(t))
	if err != nil {
		t.Fatalf("failed to read gremlins config: %v", err)
	}
	return string(data)
}

func TestGremlinsConfigExists(t *testing.T) {
	if _, err := os.Stat(gremlinsConfigPath(t)); err != nil {
		t.Fatalf("gremlins config not found: %v", err)
	}
}

func TestGremlinsConfigTargetsTechsPackage(t *testing.T) {
	content := readGremlinsConfig(t)
	if !strings.Contains(content, "./techs") {
		t.Fatal("gremlins config must target the techs package for detection logic mutation testing")
	}
}

func TestGremlinsConfigUsesEmptyBuildTags(t *testing.T) {
	content := readGremlinsConfig(t)
	if !strings.Contains(content, `tags: ""`) {
		t.Fatal(`gremlins config must set unleash.tags to "" so mutation tests run without build tags`)
	}
}

func TestGremlinsConfigDefinesThresholds(t *testing.T) {
	content := readGremlinsConfig(t)
	if !strings.Contains(content, "threshold:") {
		t.Fatal("gremlins config must define unleash.threshold for quality gates")
	}
	if !strings.Contains(content, "efficacy:") || !strings.Contains(content, "mutant-coverage:") {
		t.Fatal("gremlins config must define efficacy and mutant-coverage thresholds")
	}
	if !strings.Contains(content, "mutant-coverage: 80") {
		t.Fatal("gremlins config must set mutant-coverage threshold to 80 for Phase 1")
	}
}

func TestGremlinsConfigSetsTimeoutCoefficient(t *testing.T) {
	content := readGremlinsConfig(t)
	if !strings.Contains(content, "timeout-coefficient:") {
		t.Fatal("gremlins config must set unleash.timeout-coefficient so mutation runs do not time out")
	}
}

func TestMutationTestScriptExists(t *testing.T) {
	info, err := os.Stat(mutationTestScriptPath(t))
	if err != nil {
		t.Fatalf("mutation test script not found: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Fatal("mutation test script must be executable")
	}
}

func TestMutationTestScriptRunsTechsPackage(t *testing.T) {
	content, err := os.ReadFile(mutationTestScriptPath(t))
	if err != nil {
		t.Fatalf("failed to read mutation test script: %v", err)
	}
	script := string(content)
	if !strings.Contains(script, "./techs") {
		t.Fatal("mutation test script must run gremlins against ./techs")
	}
	if !strings.Contains(script, `--tags=""`) {
		t.Fatal(`mutation test script must pass --tags="" to gremlins unleash`)
	}
}

func TestGremlinsDryRunIsRunnable(t *testing.T) {
	if _, err := exec.LookPath("gremlins"); err != nil {
		t.Skip("gremlins not installed")
	}

	cmd := exec.Command("scripts/mutation-test.sh", "--dry-run")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gremlins dry-run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Dry run completed") {
		t.Fatalf("gremlins dry-run did not complete successfully:\n%s", out)
	}
}
