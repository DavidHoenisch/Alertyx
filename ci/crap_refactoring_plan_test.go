package ci

import (
	"math"
	"os"
	"testing"
)

func TestCrapRefactoringPlanFileExists(t *testing.T) {
	path := crapRefactoringPlanPath(repoRoot(t))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("crap refactoring plan file not found: %v", err)
	}
}

func TestCrapRefactoringPlanValidStructure(t *testing.T) {
	plan, err := LoadCrapRefactoringPlan(repoRoot(t))
	if err != nil {
		t.Fatalf("load crap refactoring plan: %v", err)
	}

	if plan.Tool != "crap-refactoring-plan" {
		t.Fatalf("expected tool crap-refactoring-plan, got %q", plan.Tool)
	}
	if plan.Generated == "" {
		t.Fatal("plan must record the generation date")
	}
	if plan.Source == "" {
		t.Fatal("plan must reference the crap baseline source")
	}
	if plan.CrapThreshold != crapMediumMax {
		t.Fatalf("crap_threshold %.1f must match medium risk max %.1f", plan.CrapThreshold, crapMediumMax)
	}
	if plan.TargetCrap != crapMediumMax {
		t.Fatalf("target_crap %.1f must match medium risk max %.1f", plan.TargetCrap, crapMediumMax)
	}
	if plan.PlanCount != len(plan.Functions) {
		t.Fatalf("plan_count %d does not match function count %d", plan.PlanCount, len(plan.Functions))
	}

	for _, entry := range plan.Functions {
		if entry.CurrentCrapScore <= plan.CrapThreshold {
			t.Fatalf("%s in %s current_crap_score %.1f must exceed threshold %.1f", entry.Function, entry.File, entry.CurrentCrapScore, plan.CrapThreshold)
		}
		if entry.ProjectedCrapScore > plan.TargetCrap {
			t.Fatalf("%s projected_crap_score %.1f must be at or below target %.1f", entry.Function, entry.ProjectedCrapScore, plan.TargetCrap)
		}
		if entry.TargetComplexity <= 0 {
			t.Fatalf("%s must specify positive target_complexity", entry.Function)
		}
		if entry.TargetCoverage <= 0 {
			t.Fatalf("%s must specify positive target_coverage", entry.Function)
		}
		if len(entry.Steps) == 0 {
			t.Fatalf("%s must include at least one refactoring step", entry.Function)
		}
		if entry.Summary == "" {
			t.Fatalf("%s must include a summary", entry.Function)
		}
		if entry.Strategy == "" {
			t.Fatalf("%s must include a strategy", entry.Function)
		}
		if entry.TestApproach == "" {
			t.Fatalf("%s must include a test_approach", entry.Function)
		}

		wantProjected := ComputeCRAP(entry.TargetComplexity, entry.TargetCoverage)
		if math.Abs(entry.ProjectedCrapScore-wantProjected) > 0.5 {
			t.Fatalf("%s projected_crap_score %.1f does not match computed %.1f", entry.Function, entry.ProjectedCrapScore, wantProjected)
		}
	}
}

func TestCrapRefactoringPlanCoversHighCRAPFunctions(t *testing.T) {
	root := repoRoot(t)

	crapBaseline, err := LoadCrapBaseline(root)
	if err != nil {
		t.Fatalf("load crap baseline: %v", err)
	}

	plan, err := LoadCrapRefactoringPlan(root)
	if err != nil {
		t.Fatalf("load crap refactoring plan: %v", err)
	}

	high := crapBaseline.HighCRAP()
	if len(high) == 0 {
		t.Fatal("crap baseline must document high-CRAP functions")
	}
	if len(plan.Functions) != len(high) {
		t.Fatalf("plan must cover all %d high-CRAP functions, got %d plans", len(high), len(plan.Functions))
	}

	for _, entry := range high {
		planEntry, ok := plan.FindPlan(entry.File, entry.Function)
		if !ok {
			t.Fatalf("refactoring plan must cover high-CRAP function %s in %s", entry.Function, entry.File)
		}
		if planEntry.CurrentCrapScore != entry.CrapScore {
			t.Fatalf("%s current_crap_score %.1f must match baseline %.1f", entry.Function, planEntry.CurrentCrapScore, entry.CrapScore)
		}
		if planEntry.CurrentComplexity != entry.Complexity {
			t.Fatalf("%s current_complexity %d must match baseline %d", entry.Function, planEntry.CurrentComplexity, entry.Complexity)
		}
		if planEntry.CurrentCoverage != entry.Coverage {
			t.Fatalf("%s current_coverage %.1f must match baseline %.1f", entry.Function, planEntry.CurrentCoverage, entry.Coverage)
		}
	}
}

func TestCrapRefactoringPlanByPriority(t *testing.T) {
	plan, err := LoadCrapRefactoringPlan(repoRoot(t))
	if err != nil {
		t.Fatalf("load crap refactoring plan: %v", err)
	}

	ordered := plan.ByPriority()
	if len(ordered) < 2 {
		t.Fatal("plan must include at least two functions for priority ordering")
	}
	if ordered[0].Priority >= ordered[1].Priority {
		t.Fatalf("ByPriority must return ascending priority, got %d then %d", ordered[0].Priority, ordered[1].Priority)
	}
}
