// Package integration provides helpers for running Alertyx eBPF tests in Vagrant VMs.
package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/bpf"
	"github.com/DavidHoenisch/Alertyx/techs"
)

const (
	DefaultLoadTimeout    = 30 * time.Second
	DefaultCollectTimeout = 5 * time.Second
)

// SkipUnlessIntegration skips t when not built with -tags=integration.
func SkipUnlessIntegration(t *testing.T) {
	t.Helper()
	if !IntegrationBuild() {
		t.Skip("skipping integration test; rebuild with -tags=integration")
	}
}

// SkipUnlessRoot skips t when not running as root (required for eBPF).
func SkipUnlessRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping integration test; eBPF requires root")
	}
}

// RepoRoot returns the absolute path to the Alertyx repository root.
func RepoRoot() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("unable to determine harness location")
	}
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	return filepath.Abs(root)
}

// ScanResult pairs a technique finding with the event that triggered it.
type ScanResult struct {
	Tech    techs.Tech
	Event   events.Event
	Finding techs.Finding
}

// ScanEvents runs each event through the given techniques and returns all findings.
func ScanEvents(techniqueList []techs.Tech, evs []events.Event) []ScanResult {
	var results []ScanResult
	for _, ev := range evs {
		for _, technique := range techniqueList {
			finding := technique.Scan(ev)
			if finding.Found {
				results = append(results, ScanResult{
					Tech:    technique,
					Event:   ev,
					Finding: finding,
				})
			}
		}
	}
	return results
}

// FirstFinding returns the first ScanResult for the given technique name prefix (e.g. "L1005").
func FirstFinding(results []ScanResult, techniquePrefix string) (ScanResult, bool) {
	for _, result := range results {
		switch result.Tech.(type) {
		case techs.L1002:
			if techniquePrefix == "L1002" {
				return result, true
			}
		case techs.L1005:
			if techniquePrefix == "L1005" {
				return result, true
			}
		case techs.T1098:
			if techniquePrefix == "T1098" {
				return result, true
			}
		}
	}
	return ScanResult{}, false
}

// OpenEvent builds a synthetic Open event for offline technique validation.
func OpenEvent(filename string, flags int32, pid, uid uint32, pwd string) *events.Open {
	ev := &events.Open{
		Flags: flags,
	}
	ev.Pid = pid
	ev.Uid = uid
	copy(ev.Filename[:], filename)
	copy(ev.Pwd[:], pwd)
	return ev
}

// ExecEvent builds a synthetic Exec event for correlate.Bin lookups in tests.
func ExecEvent(argv string, pid, uid uint32) *events.Exec {
	ev := &events.Exec{}
	ev.Pid = pid
	ev.Uid = uid
	copy(ev.Argv[:], argv)
	return ev
}

// Harness manages eBPF event collection during integration tests.
type Harness struct {
	t           *testing.T
	ctx         events.Ctx
	evChan      chan events.Event
	stop        chan struct{}
	sourceCount int
	mu          sync.Mutex
	collected   []events.Event
	loadErrors  []string
}

// NewHarness creates an integration test harness. Call Start before triggering actions.
func NewHarness(t *testing.T) *Harness {
	t.Helper()
	return &Harness{
		t:      t,
		ctx:    events.NewContext(),
		evChan: make(chan events.Event, 256),
		stop:   make(chan struct{}),
	}
}

// Start loads the given eBPF sources. OpenBPF is used when sources is empty.
func (h *Harness) Start(sources ...func(chan events.Event, events.Ctx)) error {
	if len(sources) == 0 {
		sources = []func(chan events.Event, events.Ctx){bpf.OpenBPF}
	}

	h.sourceCount = len(sources)
	h.ctx.LoadWg.Add(len(sources))

	go h.collectLoop()
	go h.errorLoop()

	for _, source := range sources {
		go source(h.evChan, h.ctx)
	}

	return h.waitLoaded()
}

// Stop tears down eBPF probes and background collectors.
func (h *Harness) Stop() {
	for i := 0; i < h.sourceCount; i++ {
		h.ctx.Quit <- true
	}
	close(h.stop)
}

// Collected returns a snapshot of events captured since Start.
func (h *Harness) Collected() []events.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]events.Event, len(h.collected))
	copy(out, h.collected)
	return out
}

// LoadErrors returns eBPF module load or attach errors observed during Start.
func (h *Harness) LoadErrors() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.loadErrors))
	copy(out, h.loadErrors)
	return out
}

// RunCmd executes a command and waits for completion.
func (h *Harness) RunCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = h.workDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, out)
	}
	return nil
}

// RunShell executes a shell script snippet.
func (h *Harness) RunShell(script string) error {
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = h.workDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bash -c %q: %w\n%s", script, err, out)
	}
	return nil
}

// RunAndWait executes fn while polling for a technique finding until timeout.
func (h *Harness) RunAndWait(technique techs.Tech, timeout time.Duration, fn func() error) (ScanResult, bool) {
	errCh := make(chan error, 1)
	go func() {
		errCh <- fn()
	}()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			if err != nil {
				h.t.Fatalf("trigger action failed: %v", err)
			}
		default:
		}

		for _, result := range ScanEvents([]techs.Tech{technique}, h.Collected()) {
			return result, true
		}
		time.Sleep(50 * time.Millisecond)
	}

	select {
	case err := <-errCh:
		if err != nil {
			h.t.Fatalf("trigger action failed: %v", err)
		}
	default:
	}

	return ScanResult{}, false
}

func (h *Harness) workDir() string {
	root, err := RepoRoot()
	if err != nil {
		h.t.Fatalf("repo root: %v", err)
	}
	return root
}

func (h *Harness) collectLoop() {
	for {
		select {
		case ev := <-h.evChan:
			events.Log(ev)
			h.mu.Lock()
			h.collected = append(h.collected, ev)
			h.mu.Unlock()
		case <-h.stop:
			return
		}
	}
}

func (h *Harness) errorLoop() {
	for {
		select {
		case errMsg := <-h.ctx.Error:
			h.mu.Lock()
			h.loadErrors = append(h.loadErrors, errMsg)
			h.mu.Unlock()
		case <-h.stop:
			return
		}
	}
}

func (h *Harness) waitLoaded() error {
	loadDone := make(chan struct{})
	go func() {
		h.ctx.LoadWg.Wait()
		close(loadDone)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), DefaultLoadTimeout)
	defer cancel()

	select {
	case <-loadDone:
		if errs := h.LoadErrors(); len(errs) > 0 {
			return fmt.Errorf("eBPF load failed: %s", errs[0])
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for eBPF modules after %s", DefaultLoadTimeout)
	}
}
