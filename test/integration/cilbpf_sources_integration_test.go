//go:build integration

package integration

import (
	"testing"

	"github.com/DavidHoenisch/Alertyx/events/cilbpf"
)

func TestIntegrationAllSourcesLoadOnKernel(t *testing.T) {
	SkipUnlessIntegration(t)
	SkipUnlessRoot(t)

	release := KernelRelease()
	t.Logf("loading all cilbpf sources on kernel %s", release)

	h := NewHarness(t)
	defer h.Stop()

	if err := h.Start(cilbpf.AllSources()...); err != nil {
		t.Fatalf("Start all sources on kernel %s: %v", release, err)
	}

	if errs := h.LoadErrors(); len(errs) > 0 {
		t.Fatalf("load errors on kernel %s: %v", release, errs)
	}
}
