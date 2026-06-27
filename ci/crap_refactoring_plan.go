package ci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CrapRefactoringPlanEntry documents how to reduce CRAP for a high-risk function.
type CrapRefactoringPlanEntry struct {
	Package            string   `json:"package"`
	Function           string   `json:"function"`
	File               string   `json:"file"`
	Line               int      `json:"line"`
	CurrentCrapScore   float64  `json:"current_crap_score"`
	CurrentComplexity  int      `json:"current_complexity"`
	CurrentCoverage    float64  `json:"current_coverage"`
	Priority           int      `json:"priority"`
	Strategy           string   `json:"strategy"`
	Summary            string   `json:"summary"`
	Steps              []string `json:"steps"`
	TestApproach       string   `json:"test_approach"`
	TargetComplexity   int      `json:"target_complexity"`
	TargetCoverage     float64  `json:"target_coverage"`
	ProjectedCrapScore float64  `json:"projected_crap_score"`
}

// CrapRefactoringPlan captures refactoring guidance for functions exceeding the CRAP threshold.
type CrapRefactoringPlan struct {
	Tool          string                     `json:"tool"`
	Generated     string                     `json:"generated"`
	Source        string                     `json:"source"`
	CrapThreshold float64                    `json:"crap_threshold"`
	TargetCrap    float64                    `json:"target_crap"`
	PlanCount     int                        `json:"plan_count"`
	Functions     []CrapRefactoringPlanEntry `json:"functions"`
}

func crapRefactoringPlanPath(root string) string {
	return filepath.Join(root, "ci", "crap-refactoring-plan.json")
}

// LoadCrapRefactoringPlan reads the documented refactoring plan from disk.
func LoadCrapRefactoringPlan(root string) (CrapRefactoringPlan, error) {
	data, err := os.ReadFile(crapRefactoringPlanPath(root))
	if err != nil {
		return CrapRefactoringPlan{}, fmt.Errorf("read crap refactoring plan: %w", err)
	}

	var plan CrapRefactoringPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return CrapRefactoringPlan{}, fmt.Errorf("parse crap refactoring plan: %w", err)
	}
	return plan, nil
}

// FindPlan returns the refactoring plan entry for a function in a given file, if present.
func (p CrapRefactoringPlan) FindPlan(file, function string) (CrapRefactoringPlanEntry, bool) {
	for _, entry := range p.Functions {
		if entry.File == file && entry.Function == function {
			return entry, true
		}
	}
	return CrapRefactoringPlanEntry{}, false
}

// ByPriority returns plan entries sorted by ascending priority value.
func (p CrapRefactoringPlan) ByPriority() []CrapRefactoringPlanEntry {
	result := make([]CrapRefactoringPlanEntry, len(p.Functions))
	copy(result, p.Functions)
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Priority < result[i].Priority {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	return result
}
