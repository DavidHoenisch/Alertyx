package techs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestL1002MitigateSetsShadowPermissions(t *testing.T) {
	shadow := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(shadow, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	oldPath := shadowFilePath
	shadowFilePath = shadow
	t.Cleanup(func() { shadowFilePath = oldPath })

	if err := (L1002{}).Mitigate(); err != nil {
		t.Fatalf("Mitigate() error: %v", err)
	}

	info, err := os.Stat(shadow)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if got := info.Mode().Perm(); got != shadowFileMode {
		t.Fatalf("permissions = %o, want %o", got, shadowFileMode)
	}
}
