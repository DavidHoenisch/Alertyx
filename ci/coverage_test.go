package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const minPackageCoverage = 70.0

var coveragePercentRE = regexp.MustCompile(`coverage: ([0-9]+\.[0-9]+)% of statements`)

func runCoverageReport(t *testing.T, root, profilePath, htmlPath string, packages ...string) []byte {
	t.Helper()

	args := append([]string{"test", "-coverprofile=" + profilePath}, packages...)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test -coverprofile failed:\n%s\n%v", output, err)
	}

	info, err := os.Stat(profilePath)
	if err != nil {
		t.Fatalf("coverage profile not created: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("coverage profile is empty")
	}

	funcCmd := exec.Command("go", "tool", "cover", "-func="+profilePath)
	funcOutput, err := funcCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go tool cover -func failed: %v\n%s", err, funcOutput)
	}
	if !strings.Contains(string(funcOutput), "total:") {
		t.Fatal("coverage func report missing total line")
	}

	htmlCmd := exec.Command("go", "tool", "cover", "-html="+profilePath, "-o", htmlPath)
	htmlOutput, err := htmlCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go tool cover -html failed: %v\n%s", err, htmlOutput)
	}
	htmlInfo, err := os.Stat(htmlPath)
	if err != nil {
		t.Fatalf("HTML coverage report not created: %v", err)
	}
	if htmlInfo.Size() == 0 {
		t.Fatal("HTML coverage report is empty")
	}

	return output
}

func parseCoveragePercent(output []byte) (float64, bool) {
	match := coveragePercentRE.FindSubmatch(output)
	if len(match) != 2 {
		return 0, false
	}
	pct, err := strconv.ParseFloat(string(match[1]), 64)
	if err != nil {
		return 0, false
	}
	return pct, true
}

func TestCoverageReport(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	profilePath := filepath.Join(tmp, "coverage.out")
	htmlPath := filepath.Join(tmp, "coverage.html")

	targetPackages := []string{"./events", "./techs"}
	output := runCoverageReport(t, root, profilePath, htmlPath, targetPackages...)

	for _, pkg := range []string{"events", "techs"} {
		if !strings.Contains(string(output), pkg) {
			t.Fatalf("coverage output missing package %q", pkg)
		}
	}

	for _, pkg := range targetPackages {
		pkgCmd := exec.Command("go", "test", "-cover", pkg)
		pkgCmd.Dir = root
		pkgOutput, err := pkgCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go test -cover %s failed:\n%s\n%v", pkg, pkgOutput, err)
		}
		pct, ok := parseCoveragePercent(pkgOutput)
		if !ok {
			t.Fatalf("could not parse coverage percentage for %s:\n%s", pkg, pkgOutput)
		}
		if pct < minPackageCoverage {
			t.Fatalf("%s coverage %.1f%% below minimum %.1f%%", pkg, pct, minPackageCoverage)
		}
	}
}
