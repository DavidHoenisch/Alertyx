package ci

import (
	"os"
	"testing"
)

func TestCoverageBaselineFileExists(t *testing.T) {
	path := coverageBaselinePath(repoRoot(t))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("coverage baseline file not found: %v", err)
	}
}

func TestCoverageBaselineValidStructure(t *testing.T) {
	baseline, err := LoadCoverageBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load coverage baseline: %v", err)
	}

	if baseline.Tool != "go cover" {
		t.Fatalf("expected tool go cover, got %q", baseline.Tool)
	}
	if baseline.ToolVersion == "" {
		t.Fatal("baseline must record the go tool version")
	}
	if baseline.Generated == "" {
		t.Fatal("baseline must record the generation date")
	}
	if baseline.CoverageTarget != defaultCoverageTarget {
		t.Fatalf("expected coverage target %.0f, got %.0f", defaultCoverageTarget, baseline.CoverageTarget)
	}
	if baseline.TotalCoverage < 0 {
		t.Fatal("baseline must record a non-negative total coverage")
	}
	if baseline.PackagesTested != len(baseline.Packages)-baseline.PackagesNoTests {
		t.Fatalf("packages_tested %d does not match package entries %d minus no-test packages %d",
			baseline.PackagesTested, len(baseline.Packages), baseline.PackagesNoTests)
	}
	if baseline.UnderTargetCount != len(baseline.UnderTarget()) {
		t.Fatalf("under_target_count %d does not match computed count %d", baseline.UnderTargetCount, len(baseline.UnderTarget()))
	}
}

func TestCoverageBaselineDocumentsSuspectedHighCRAPFunctions(t *testing.T) {
	baseline, err := LoadCoverageBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load coverage baseline: %v", err)
	}

	suspected := []struct {
		file     string
		function string
	}{
		{"events/events.go", "readEvents"},
		{"utils/monitor.go", "AlertyxMonitor"},
		{"analysis/analysis.go", "processTechs"},
		{"correlate/correlation.go", "Summarize"},
	}

	for _, fn := range suspected {
		entry, ok := baseline.FindFunction(fn.file, fn.function)
		if !ok {
			t.Fatalf("baseline must track suspected high-CRAP function %s in %s", fn.function, fn.file)
		}
		if entry.Coverage < 0 {
			t.Fatalf("%s coverage must be non-negative, got %.1f", fn.function, entry.Coverage)
		}
	}
}

func TestCoverageBaselineUnderTargetPackages(t *testing.T) {
	baseline, err := LoadCoverageBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load coverage baseline: %v", err)
	}

	under := baseline.UnderTarget()
	if len(under) == 0 {
		t.Fatal("baseline must document at least one package under the coverage target")
	}

	for _, entry := range under {
		if entry.Coverage >= baseline.CoverageTarget {
			t.Fatalf("package %s has coverage %.1f, expected < %.0f", entry.Path, entry.Coverage, baseline.CoverageTarget)
		}
	}
}

func TestCoverageBaselineDocumentsOnlyCIPackageHasTests(t *testing.T) {
	baseline, err := LoadCoverageBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load coverage baseline: %v", err)
	}

	var withTests int
	for _, entry := range baseline.Packages {
		if entry.HasTests {
			withTests++
			if entry.Path != "ci" {
				t.Fatalf("only ci package should have tests, got %s", entry.Path)
			}
		}
	}
	if withTests != 1 {
		t.Fatalf("expected exactly one package with tests, got %d", withTests)
	}
}

func TestCoverageBaselineDocumentsPackagesWithoutTests(t *testing.T) {
	baseline, err := LoadCoverageBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load coverage baseline: %v", err)
	}

	entry, ok := baseline.FindPackage("common")
	if !ok {
		t.Fatal("baseline must include the common package")
	}
	if entry.HasTests {
		t.Fatal("common package must be marked as having no tests")
	}
}
