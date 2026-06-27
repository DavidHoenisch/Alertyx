//go:build integration

package integration

// IntegrationBuild reports whether tests were compiled with -tags=integration.
func IntegrationBuild() bool {
	return true
}
