package ci

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

const (
	crapLowMax    = 5.0
	crapMediumMax = 30.0
)

// CrapEntry records CRAP score and inputs for a single function.
type CrapEntry struct {
	Package    string  `json:"package"`
	Function   string  `json:"function"`
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Complexity int     `json:"complexity"`
	Coverage   float64 `json:"coverage"`
	CrapScore  float64 `json:"crap_score"`
	RiskLevel  string  `json:"risk_level"`
}

// CrapBaseline captures CRAP scores derived from gocyclo and coverage baselines.
type CrapBaseline struct {
	Tool            string      `json:"tool"`
	Generated       string      `json:"generated"`
	Formula         string      `json:"formula"`
	Sources         []string    `json:"sources"`
	HighCrapCount   int         `json:"high_crap_count"`
	MediumCrapCount int         `json:"medium_crap_count"`
	LowCrapCount    int         `json:"low_crap_count"`
	Functions       []CrapEntry `json:"functions"`
}

func crapBaselinePath(root string) string {
	return filepath.Join(root, "ci", "crap-baseline.json")
}

// ComputeCRAP calculates the Change Risk Anti-Patterns score for a function.
// Formula: complexity^2 * (1 - coverage/100)^3 + complexity
func ComputeCRAP(complexity int, coverage float64) float64 {
	if complexity <= 0 {
		return 0
	}
	uncovered := 1.0 - coverage/100.0
	return float64(complexity*complexity)*math.Pow(uncovered, 3) + float64(complexity)
}

// CrapRiskLevel classifies a CRAP score as low, medium, or high.
func CrapRiskLevel(score float64) string {
	switch {
	case score < crapLowMax:
		return "low"
	case score <= crapMediumMax:
		return "medium"
	default:
		return "high"
	}
}

// LoadCrapBaseline reads the documented CRAP baseline from disk.
func LoadCrapBaseline(root string) (CrapBaseline, error) {
	data, err := os.ReadFile(crapBaselinePath(root))
	if err != nil {
		return CrapBaseline{}, fmt.Errorf("read crap baseline: %w", err)
	}

	var baseline CrapBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return CrapBaseline{}, fmt.Errorf("parse crap baseline: %w", err)
	}
	return baseline, nil
}

// HighCRAP returns functions with CRAP score above the medium risk threshold.
func (b CrapBaseline) HighCRAP() []CrapEntry {
	var result []CrapEntry
	for _, entry := range b.Functions {
		if entry.CrapScore > crapMediumMax {
			result = append(result, entry)
		}
	}
	return result
}

// ByRiskLevel returns functions matching the given risk level.
func (b CrapBaseline) ByRiskLevel(level string) []CrapEntry {
	var result []CrapEntry
	for _, entry := range b.Functions {
		if entry.RiskLevel == level {
			result = append(result, entry)
		}
	}
	return result
}

// FindFunction returns the baseline entry for a function in a given file, if present.
func (b CrapBaseline) FindFunction(file, function string) (CrapEntry, bool) {
	for _, entry := range b.Functions {
		if entry.File == file && entry.Function == function {
			return entry, true
		}
	}
	return CrapEntry{}, false
}
