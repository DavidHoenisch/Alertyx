package ci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const defaultComplexityThreshold = 10

// GocycloEntry records cyclomatic complexity for a single function.
type GocycloEntry struct {
	Complexity int    `json:"complexity"`
	Package    string `json:"package"`
	Function   string `json:"function"`
	File       string `json:"file"`
	Line       int    `json:"line"`
}

// GocycloBaseline captures a gocyclo snapshot for change-risk tracking.
type GocycloBaseline struct {
	Tool                string         `json:"tool"`
	ToolVersion         string         `json:"tool_version"`
	Generated           string         `json:"generated"`
	ComplexityThreshold int            `json:"complexity_threshold"`
	TotalFunctions      int            `json:"total_functions"`
	OverThresholdCount  int            `json:"over_threshold_count"`
	MaxComplexity       int            `json:"max_complexity"`
	Functions           []GocycloEntry `json:"functions"`
}

func gocycloBaselinePath(root string) string {
	return filepath.Join(root, "ci", "gocyclo-baseline.json")
}

// LoadGocycloBaseline reads the documented gocyclo baseline from disk.
func LoadGocycloBaseline(root string) (GocycloBaseline, error) {
	data, err := os.ReadFile(gocycloBaselinePath(root))
	if err != nil {
		return GocycloBaseline{}, fmt.Errorf("read gocyclo baseline: %w", err)
	}

	var baseline GocycloBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return GocycloBaseline{}, fmt.Errorf("parse gocyclo baseline: %w", err)
	}
	return baseline, nil
}

// OverThreshold returns functions whose complexity exceeds the baseline threshold.
func (b GocycloBaseline) OverThreshold() []GocycloEntry {
	threshold := b.ComplexityThreshold
	if threshold == 0 {
		threshold = defaultComplexityThreshold
	}

	var result []GocycloEntry
	for _, entry := range b.Functions {
		if entry.Complexity > threshold {
			result = append(result, entry)
		}
	}
	return result
}

// FindFunction returns the baseline entry for a function in a given file, if present.
func (b GocycloBaseline) FindFunction(file, function string) (GocycloEntry, bool) {
	for _, entry := range b.Functions {
		if entry.File == file && entry.Function == function {
			return entry, true
		}
	}
	return GocycloEntry{}, false
}
