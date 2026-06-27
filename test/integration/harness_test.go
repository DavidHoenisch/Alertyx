package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/techs"
)

func TestHarnessFileExists(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("RepoRoot: %v", err)
	}
	path := filepath.Join(root, "test", "integration", "harness.go")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("harness.go not found: %v", err)
	}
}

func TestIntegrationBuildWithoutTag(t *testing.T) {
	if IntegrationBuild() {
		t.Skip("only applies to default (non-integration) builds")
	}
	if IntegrationBuild() {
		t.Fatal("IntegrationBuild should be false without -tags=integration")
	}
}

func TestSkipUnlessIntegrationSkips(t *testing.T) {
	if IntegrationBuild() {
		t.Skip("only applies to default (non-integration) builds")
	}
	SkipUnlessIntegration(t)
	t.Fatal("SkipUnlessIntegration should have skipped the test")
}

func TestRepoRootContainsGoMod(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("RepoRoot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("go.mod not found under repo root %q: %v", root, err)
	}
}

func TestScanEventsDetectsL1005TmpWrite(t *testing.T) {
	ev := OpenEvent("/tmp/alertyx-integration-test", int32(os.O_WRONLY), 1000, 1000, "/tmp")
	results := ScanEvents([]techs.Tech{techs.L1005{}}, []events.Event{ev})
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].Finding.Level != techs.LevelWarn {
		t.Fatalf("expected LevelWarn, got %d", results[0].Finding.Level)
	}
}

func TestScanEventsDetectsL1005DevShmWrite(t *testing.T) {
	ev := OpenEvent("/dev/shm/alertyx-test", int32(os.O_WRONLY), 1001, 1000, "/dev/shm")
	results := ScanEvents([]techs.Tech{techs.L1005{}}, []events.Event{ev})
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].Finding.Level != techs.LevelErr {
		t.Fatalf("expected LevelErr, got %d", results[0].Finding.Level)
	}
}

func TestScanEventsDetectsT1098AuthorizedKeysWrite(t *testing.T) {
	ev := OpenEvent("/home/user/.ssh/authorized_keys", int32(os.O_WRONLY), 1002, 1000, "/home/user/.ssh")
	ev.RetVal = 0
	ev.Uid = 1000
	results := ScanEvents([]techs.Tech{techs.T1098{}}, []events.Event{ev})
	if len(results) != 1 {
		t.Fatalf("expected 1 finding for cross-user authorized_keys write, got %d", len(results))
	}
	if results[0].Finding.Level != techs.LevelCrit {
		t.Fatalf("expected LevelCrit, got %d", results[0].Finding.Level)
	}
}

func TestScanEventsDetectsL1002ShadowAccess(t *testing.T) {
	events.Log(ExecEvent("/usr/bin/cat", 2000, 0))
	ev := OpenEvent("/etc/shadow", int32(os.O_RDONLY), 2000, 0, "/")
	results := ScanEvents([]techs.Tech{techs.L1002{}}, []events.Event{ev})
	if len(results) != 1 {
		t.Fatalf("expected 1 finding for non-privileged /etc/shadow access, got %d", len(results))
	}
	if results[0].Finding.Level != techs.LevelWarn {
		t.Fatalf("expected LevelWarn, got %d", results[0].Finding.Level)
	}
}

func TestFirstFindingMatchesTechnique(t *testing.T) {
	ev := OpenEvent("/tmp/first-finding", int32(os.O_WRONLY), 1003, 1000, "/tmp")
	results := ScanEvents([]techs.Tech{techs.L1005{}}, []events.Event{ev})
	got, ok := FirstFinding(results, "L1005")
	if !ok {
		t.Fatal("FirstFinding should match L1005 result")
	}
	if got.Event.FetchPid() != 1003 {
		t.Fatalf("expected pid 1003, got %d", got.Event.FetchPid())
	}
}
