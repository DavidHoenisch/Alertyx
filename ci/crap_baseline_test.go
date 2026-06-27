package ci

import (
	"math"
	"os"
	"testing"
)

func TestCrapBaselineFileExists(t *testing.T) {
	path := crapBaselinePath(repoRoot(t))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("crap baseline file not found: %v", err)
	}
}

func TestComputeCRAPMatchesFormula(t *testing.T) {
	tests := []struct {
		name       string
		complexity int
		coverage   float64
		want       float64
	}{
		{"zero coverage high complexity", 21, 0.0, 462.0},
		{"zero coverage moderate complexity", 15, 0.0, 240.0},
		{"zero coverage low complexity", 3, 0.0, 12.0},
		{"full coverage zeroes risk multiplier", 21, 100.0, 21.0},
		{"partial coverage reduces score", 10, 50.0, 22.5},
		{"zero complexity", 0, 0.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeCRAP(tt.complexity, tt.coverage)
			if math.Abs(got-tt.want) > 0.01 {
				t.Fatalf("ComputeCRAP(%d, %.1f) = %.2f, want %.2f", tt.complexity, tt.coverage, got, tt.want)
			}
		})
	}
}

func TestCrapRiskLevelClassification(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{4.9, "low"},
		{5.0, "medium"},
		{30.0, "medium"},
		{30.1, "high"},
		{462.0, "high"},
	}

	for _, tt := range tests {
		if got := CrapRiskLevel(tt.score); got != tt.want {
			t.Fatalf("CrapRiskLevel(%.1f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestCrapBaselineValidStructure(t *testing.T) {
	baseline, err := LoadCrapBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load crap baseline: %v", err)
	}

	if baseline.Tool != "crap" {
		t.Fatalf("expected tool crap, got %q", baseline.Tool)
	}
	if baseline.Generated == "" {
		t.Fatal("baseline must record the generation date")
	}
	if baseline.Formula == "" {
		t.Fatal("baseline must record the CRAP formula")
	}
	if len(baseline.Sources) < 2 {
		t.Fatal("baseline must reference gocyclo and coverage sources")
	}
	if baseline.HighCrapCount != len(baseline.HighCRAP()) {
		t.Fatalf("high_crap_count %d does not match computed count %d", baseline.HighCrapCount, len(baseline.HighCRAP()))
	}
	if baseline.MediumCrapCount != len(baseline.ByRiskLevel("medium")) {
		t.Fatalf("medium_crap_count %d does not match computed count %d", baseline.MediumCrapCount, len(baseline.ByRiskLevel("medium")))
	}
	if baseline.LowCrapCount != len(baseline.ByRiskLevel("low")) {
		t.Fatalf("low_crap_count %d does not match computed count %d", baseline.LowCrapCount, len(baseline.ByRiskLevel("low")))
	}

	for _, entry := range baseline.Functions {
		wantScore := ComputeCRAP(entry.Complexity, entry.Coverage)
		if math.Abs(entry.CrapScore-wantScore) > 0.01 {
			t.Fatalf("%s in %s crap_score %.1f does not match computed %.1f", entry.Function, entry.File, entry.CrapScore, wantScore)
		}
		wantRisk := CrapRiskLevel(entry.CrapScore)
		if entry.RiskLevel != wantRisk {
			t.Fatalf("%s in %s risk_level %q does not match computed %q", entry.Function, entry.File, entry.RiskLevel, wantRisk)
		}
	}
}

func TestCrapBaselineDocumentsSuspectedHighCRAPFunctions(t *testing.T) {
	baseline, err := LoadCrapBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load crap baseline: %v", err)
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
		if entry.Complexity <= 0 {
			t.Fatalf("%s must record positive complexity", fn.function)
		}
		if entry.Coverage < 0 {
			t.Fatalf("%s coverage must be non-negative, got %.1f", fn.function, entry.Coverage)
		}
	}
}

func TestCrapBaselineHighCRAPFunctions(t *testing.T) {
	baseline, err := LoadCrapBaseline(repoRoot(t))
	if err != nil {
		t.Fatalf("load crap baseline: %v", err)
	}

	high := baseline.HighCRAP()
	if len(high) == 0 {
		t.Fatal("baseline must document at least one high-CRAP function")
	}

	wantHigh := []struct {
		file     string
		function string
		minScore float64
	}{
		{"utils/monitor.go", "AlertyxMonitor", 30.0},
		{"events/events.go", "readEvents", 30.0},
	}

	for _, fn := range wantHigh {
		entry, ok := baseline.FindFunction(fn.file, fn.function)
		if !ok {
			t.Fatalf("baseline must track high-CRAP function %s in %s", fn.function, fn.file)
		}
		if entry.RiskLevel != "high" {
			t.Fatalf("%s must be classified as high risk, got %q", fn.function, entry.RiskLevel)
		}
		if entry.CrapScore <= fn.minScore {
			t.Fatalf("%s crap_score %.1f must exceed %.1f", fn.function, entry.CrapScore, fn.minScore)
		}
	}

	for _, entry := range high {
		if entry.CrapScore <= crapMediumMax {
			t.Fatalf("function %s in %s has crap_score %.1f, expected > %.0f", entry.Function, entry.File, entry.CrapScore, crapMediumMax)
		}
	}
}
