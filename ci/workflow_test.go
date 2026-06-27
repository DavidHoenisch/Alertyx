package ci

import (
	"encoding/json"
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

func workflowPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), ".github", "workflows", "test.yml")
}

func branchProtectionPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "ci", "branch-protection.json")
}

func readWorkflow(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(workflowPath(t))
	if err != nil {
		t.Fatalf("failed to read workflow: %v", err)
	}
	return string(data)
}

func jobSection(content, jobName string) string {
	startMarker := "  " + jobName + ":\n"
	endMarker := "\n  test:\n"

	start := strings.Index(content, startMarker)
	if start == -1 {
		return ""
	}
	start += len(startMarker)

	if jobName == "test" {
		return content[start:]
	}

	end := strings.Index(content[start:], endMarker)
	if end == -1 {
		return content[start:]
	}
	return content[start : start+end]
}

func TestWorkflowFileExists(t *testing.T) {
	if _, err := os.Stat(workflowPath(t)); err != nil {
		t.Fatalf("workflow file not found: %v", err)
	}
}

func TestWorkflowTriggersOnPullRequest(t *testing.T) {
	content := readWorkflow(t)
	if !strings.Contains(content, "pull_request") {
		t.Fatal("workflow must trigger on pull_request events so CI runs on all PRs")
	}
}

func TestWorkflowTriggersOnPush(t *testing.T) {
	content := readWorkflow(t)
	if !strings.Contains(content, "push") {
		t.Fatal("workflow must trigger on push events")
	}
}

func TestWorkflowHasDedicatedBuildJob(t *testing.T) {
	content := readWorkflow(t)
	buildJob := jobSection(content, "build")
	if buildJob == "" {
		t.Fatal("workflow must define a dedicated build job")
	}
	if !strings.Contains(buildJob, "go build ./...") {
		t.Fatal("build job must run go build ./...")
	}
}

func TestWorkflowBuildJobHasNoContinueOnError(t *testing.T) {
	content := readWorkflow(t)
	buildJob := jobSection(content, "build")
	if buildJob == "" {
		t.Fatal("workflow must define a dedicated build job")
	}
	if strings.Contains(buildJob, "continue-on-error: true") {
		t.Fatal("build job must not use continue-on-error so failures block merge")
	}
}

func TestWorkflowTestJobDependsOnBuild(t *testing.T) {
	content := readWorkflow(t)
	testJob := jobSection(content, "test")
	if testJob == "" {
		t.Fatal("workflow must define a test job")
	}
	if !strings.Contains(testJob, "needs: build") {
		t.Fatal("test job must need build so build failures fail the workflow before tests run")
	}
}

type branchProtection struct {
	RequiredStatusChecks struct {
		Strict bool `json:"strict"`
		Checks []struct {
			Context string `json:"context"`
		} `json:"checks"`
	} `json:"required_status_checks"`
}

func branchProtectionConfig(t *testing.T) branchProtection {
	t.Helper()
	data, err := os.ReadFile(branchProtectionPath(t))
	if err != nil {
		t.Fatalf("failed to read branch protection config: %v", err)
	}

	var cfg branchProtection
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse branch protection config: %v", err)
	}
	return cfg
}

func hasRequiredCheck(t *testing.T, cfg branchProtection, context string) {
	t.Helper()
	for _, check := range cfg.RequiredStatusChecks.Checks {
		if check.Context == context {
			return
		}
	}
	t.Fatalf("branch protection must require the %s status check", context)
}

func TestWorkflowTestJobHasNoContinueOnError(t *testing.T) {
	content := readWorkflow(t)
	testJob := jobSection(content, "test")
	if testJob == "" {
		t.Fatal("workflow must define a test job")
	}
	if strings.Contains(testJob, "continue-on-error: true") {
		t.Fatal("test job must not use continue-on-error so failures block merge")
	}
}

func TestWorkflowTestJobRunsTests(t *testing.T) {
	content := readWorkflow(t)
	testJob := jobSection(content, "test")
	if testJob == "" {
		t.Fatal("workflow must define a test job")
	}
	if !strings.Contains(testJob, "go test") || !strings.Contains(testJob, "./...") {
		t.Fatal("test job must run go test ./...")
	}
}

func TestBranchProtectionRequiresBuildCheck(t *testing.T) {
	cfg := branchProtectionConfig(t)
	if !cfg.RequiredStatusChecks.Strict {
		t.Fatal("branch protection must require branches to be up to date before merging")
	}
	hasRequiredCheck(t, cfg, "Test / build")
}

func TestBranchProtectionRequiresTestCheck(t *testing.T) {
	cfg := branchProtectionConfig(t)
	if !cfg.RequiredStatusChecks.Strict {
		t.Fatal("branch protection must require branches to be up to date before merging")
	}
	hasRequiredCheck(t, cfg, "Test / test")
}

func codecovConfigPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), ".codecov.yml")
}

func TestCodecovConfigExists(t *testing.T) {
	if _, err := os.Stat(codecovConfigPath(t)); err != nil {
		t.Fatalf("codecov config not found: %v", err)
	}
}

func TestWorkflowTestJobGeneratesCoverageProfile(t *testing.T) {
	content := readWorkflow(t)
	testJob := jobSection(content, "test")
	if testJob == "" {
		t.Fatal("workflow must define a test job")
	}
	if !strings.Contains(testJob, "-coverprofile=coverage.out") {
		t.Fatal("test job must generate coverage.out for historical tracking")
	}
}

func TestWorkflowUploadsCoverageToCodecov(t *testing.T) {
	content := readWorkflow(t)
	testJob := jobSection(content, "test")
	if testJob == "" {
		t.Fatal("workflow must define a test job")
	}
	if !strings.Contains(testJob, "codecov/codecov-action@v4") {
		t.Fatal("test job must upload coverage to Codecov for tracking over time")
	}
	if !strings.Contains(testJob, "files: ./coverage.out") {
		t.Fatal("codecov upload must reference the generated coverage.out file")
	}
}

func readmePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "README.md")
}

func readReadme(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(readmePath(t))
	if err != nil {
		t.Fatalf("failed to read README: %v", err)
	}
	return string(data)
}

func TestReadmeContainsCIBadge(t *testing.T) {
	content := readReadme(t)
	badgeURL := "https://github.com/DavidHoenisch/Alertyx/actions/workflows/test.yml/badge.svg"
	workflowURL := "https://github.com/DavidHoenisch/Alertyx/actions/workflows/test.yml"
	if !strings.Contains(content, badgeURL) {
		t.Fatal("README must include a CI status badge linking to the test workflow")
	}
	if !strings.Contains(content, workflowURL) {
		t.Fatal("README CI badge must link to the test workflow page")
	}
}
