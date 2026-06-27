//go:build integration

package integration

import "testing"

func TestIntegrationBuildWithTag(t *testing.T) {
	if !IntegrationBuild() {
		t.Fatal("IntegrationBuild should be true with -tags=integration")
	}
}
