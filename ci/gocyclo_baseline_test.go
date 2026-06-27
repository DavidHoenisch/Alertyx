package ci

import (
	"os"
	"testing"
)

func TestGocycloBaselineFileExists(t *testing.T) {
	path := gocycloBaselinePath(repoRoot(t))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("gocyclo baseline file not found: %v", err)
	}
}

func TestGocycloBaselineValidStructure(t *testing.T) {
	baseline, err := LoadGocycloBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load gocyclo baseline: %v", err)
	}

	if baseline.Tool != "gocyclo" {
		t.Fatalf("expected tool gocyclo, got %q", baseline.Tool)
	}
	if baseline.ToolVersion == "" {
		t.Fatal("baseline must record the gocyclo tool version")
	}
	if baseline.Generated == "" {
		t.Fatal("baseline must record the generation date")
	}
	if baseline.ComplexityThreshold != defaultComplexityThreshold {
		t.Fatalf("expected complexity threshold %d, got %d", defaultComplexityThreshold, baseline.ComplexityThreshold)
	}
	if baseline.TotalFunctions != len(baseline.Functions) {
		t.Fatalf("total_functions %d does not match function entries %d", baseline.TotalFunctions, len(baseline.Functions))
	}
	if baseline.MaxComplexity <= 0 {
		t.Fatal("baseline must record a positive max complexity")
	}
	if baseline.OverThresholdCount != len(baseline.OverThreshold()) {
		t.Fatalf("over_threshold_count %d does not match computed count %d", baseline.OverThresholdCount, len(baseline.OverThreshold()))
	}
}

func TestGocycloBaselineDocumentsSuspectedHighComplexityFunctions(t *testing.T) {
	baseline, err := LoadGocycloBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load gocyclo baseline: %v", err)
	}

	suspected := []struct {
		file     string
		function string
		min      int
	}{
		{"utils/monitor.go", "AlertyxMonitor", 20},
		{"events/events.go", "readEvents", 14},
	}

	for _, fn := range suspected {
		entry, ok := baseline.FindFunction(fn.file, fn.function)
		if !ok {
			t.Fatalf("baseline must track suspected high-complexity function %s in %s", fn.function, fn.file)
		}
		if entry.Complexity < fn.min {
			t.Fatalf("%s complexity %d below expected minimum %d", fn.function, entry.Complexity, fn.min)
		}
	}
}

func TestGocycloBaselineOverThresholdFunctions(t *testing.T) {
	baseline, err := LoadGocycloBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load gocyclo baseline: %v", err)
	}

	over := baseline.OverThreshold()
	if len(over) == 0 {
		t.Fatal("baseline must document at least one function over the complexity threshold")
	}

	for _, entry := range over {
		if entry.Complexity <= baseline.ComplexityThreshold {
			t.Fatalf("function %s in %s has complexity %d, expected > %d", entry.Function, entry.File, entry.Complexity, baseline.ComplexityThreshold)
		}
		if entry.File == "" || entry.Function == "" || entry.Package == "" {
			t.Fatalf("over-threshold entry must include package, function, and file: %+v", entry)
		}
	}
}
