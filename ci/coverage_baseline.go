package ci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const defaultCoverageTarget = 70.0

// CoveragePackageEntry records statement coverage for a Go package.
type CoveragePackageEntry struct {
	Path     string  `json:"path"`
	Package  string  `json:"package"`
	Coverage float64 `json:"coverage"`
	HasTests bool    `json:"has_tests"`
}

// CoverageFunctionEntry records statement coverage for a single function.
type CoverageFunctionEntry struct {
	Package  string  `json:"package"`
	Function string  `json:"function"`
	File     string  `json:"file"`
	Line     int     `json:"line"`
	Coverage float64 `json:"coverage"`
}

// CoverageBaseline captures a go cover snapshot for change-risk tracking.
type CoverageBaseline struct {
	Tool             string                  `json:"tool"`
	ToolVersion      string                  `json:"tool_version"`
	Generated        string                  `json:"generated"`
	CoverageTarget   float64                 `json:"coverage_target"`
	TotalCoverage    float64                 `json:"total_coverage"`
	PackagesTested   int                     `json:"packages_tested"`
	PackagesNoTests  int                     `json:"packages_no_tests"`
	UnderTargetCount int                     `json:"under_target_count"`
	Packages         []CoveragePackageEntry  `json:"packages"`
	Functions        []CoverageFunctionEntry `json:"functions"`
}

func coverageBaselinePath(root string) string {
	return filepath.Join(root, "ci", "coverage-baseline.json")
}

// LoadCoverageBaseline reads the documented coverage baseline from disk.
func LoadCoverageBaseline(root string) (CoverageBaseline, error) {
	data, err := os.ReadFile(coverageBaselinePath(root))
	if err != nil {
		return CoverageBaseline{}, fmt.Errorf("read coverage baseline: %w", err)
	}

	var baseline CoverageBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return CoverageBaseline{}, fmt.Errorf("parse coverage baseline: %w", err)
	}
	return baseline, nil
}

// UnderTarget returns packages whose coverage is below the baseline target.
func (b CoverageBaseline) UnderTarget() []CoveragePackageEntry {
	target := b.CoverageTarget
	if target == 0 {
		target = defaultCoverageTarget
	}

	var result []CoveragePackageEntry
	for _, entry := range b.Packages {
		if entry.Coverage < target {
			result = append(result, entry)
		}
	}
	return result
}

// FindFunction returns the baseline entry for a function in a given file, if present.
func (b CoverageBaseline) FindFunction(file, function string) (CoverageFunctionEntry, bool) {
	for _, entry := range b.Functions {
		if entry.File == file && entry.Function == function {
			return entry, true
		}
	}
	return CoverageFunctionEntry{}, false
}

// FindPackage returns the baseline entry for a package path, if present.
func (b CoverageBaseline) FindPackage(path string) (CoveragePackageEntry, bool) {
	for _, entry := range b.Packages {
		if entry.Path == path {
			return entry, true
		}
	}
	return CoveragePackageEntry{}, false
}
