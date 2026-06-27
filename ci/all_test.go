package ci

import (
	"os"
	"os/exec"
	"testing"
)

// fullSuiteEnv prevents TestAllPackagesPass from recursively spawning go test ./...
// when this package is already running as part of the full suite.
const fullSuiteEnv = "ALERTYX_FULL_SUITE"

func TestAllPackagesPass(t *testing.T) {
	if os.Getenv(fullSuiteEnv) != "" {
		t.Skip("already running as part of full suite")
	}

	cmd := exec.Command("go", "test", "./...")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), fullSuiteEnv+"=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test ./... failed:\n%s\n%v", output, err)
	}
}
