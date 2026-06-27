//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/techs"
)

func TestIntegrationL1005DetectsTmpWrite(t *testing.T) {
	SkipUnlessIntegration(t)
	SkipUnlessRoot(t)

	h := NewHarness(t)
	defer h.Stop()

	if err := h.Start(events.OpenBPF); err != nil {
		t.Fatalf("Start: %v", err)
	}

	target := filepath.Join("/tmp", fmt.Sprintf("alertyx-l1005-%d", os.Getpid()))
	result, found := h.RunAndWait(techs.L1005{}, DefaultCollectTimeout, func() error {
		return h.RunShell(fmt.Sprintf("echo alertyx > %q", target))
	})
	if !found {
		t.Fatalf("L1005 did not detect write to %s; collected %d events", target, len(h.Collected()))
	}
	if result.Finding.Level != techs.LevelWarn {
		t.Fatalf("expected LevelWarn for /tmp write, got %d", result.Finding.Level)
	}
}

func TestIntegrationL1002DetectsShadowAccess(t *testing.T) {
	SkipUnlessIntegration(t)
	SkipUnlessRoot(t)

	h := NewHarness(t)
	defer h.Stop()

	if err := h.Start(events.OpenBPF, events.ExecBPF); err != nil {
		t.Fatalf("Start: %v", err)
	}

	result, found := h.RunAndWait(techs.L1002{}, DefaultCollectTimeout, func() error {
		return h.RunCmd("head", "-1", "/etc/shadow")
	})
	if !found {
		t.Fatalf("L1002 did not detect /etc/shadow access; collected %d events", len(h.Collected()))
	}
	if result.Finding.Level != techs.LevelWarn {
		t.Fatalf("expected LevelWarn for non-privileged /etc/shadow access, got %d", result.Finding.Level)
	}
}

func TestIntegrationT1098DetectsCrossUserAuthorizedKeysWrite(t *testing.T) {
	SkipUnlessIntegration(t)
	SkipUnlessRoot(t)

	h := NewHarness(t)
	defer h.Stop()

	if err := h.Start(events.OpenBPF); err != nil {
		t.Fatalf("Start: %v", err)
	}

	baseDir := filepath.Join("/tmp", fmt.Sprintf("alertyx-t1098-%d", os.Getpid()))
	keysPath := filepath.Join(baseDir, ".ssh", "authorized_keys")
	const testOwnerUID = 65534 // nobody

	result, found := h.RunAndWait(techs.T1098{}, DefaultCollectTimeout, func() error {
		script := fmt.Sprintf(`
set -e
mkdir -p %q
touch %q
chown %d:%d %q
echo "ssh-rsa AAAA alertyx-integration-test" >> %q
`, filepath.Dir(keysPath), keysPath, testOwnerUID, testOwnerUID, keysPath, keysPath)
		return h.RunShell(script)
	})
	if !found {
		t.Fatalf("T1098 did not detect cross-user authorized_keys write; collected %d events", len(h.Collected()))
	}
	if result.Finding.Level != techs.LevelCrit {
		t.Fatalf("expected LevelCrit for cross-user authorized_keys write, got %d", result.Finding.Level)
	}
}
