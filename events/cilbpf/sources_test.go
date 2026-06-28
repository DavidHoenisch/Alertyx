package cilbpf

import "testing"

func TestAllSources(t *testing.T) {
	sources := AllSources()
	if len(sources) != 4 {
		t.Fatalf("AllSources() len = %d, want 4", len(sources))
	}
	for i, source := range sources {
		if source == nil {
			t.Fatalf("AllSources()[%d] is nil", i)
		}
	}
}
