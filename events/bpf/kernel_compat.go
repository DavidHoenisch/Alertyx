package bpf

import (
	"fmt"
	"strings"
)

// SupportedKernelMajors lists kernel major versions where PPID tracking is supported.
var SupportedKernelMajors = []int{5, 6, 7}

var ppidGatherRequiredMarkers = []string{
	"bpf_get_current_task()",
	"real_parent",
	"bpf_probe_read(&parent",
	"bpf_probe_read(&event.ppid",
}

var ppidGatherForbiddenMarkers = []string{
	"ppid = 0",
	"event.ppid = task->",
	"event.ppid = parent->",
	"task->real_parent->tgid",
}

// ValidatePPIDGatherCompat checks that gatherStr uses bpf_probe_read instead of direct
// task_struct field access, which is required for verifier acceptance on kernels 5.x–7.x.
func ValidatePPIDGatherCompat(gather string) error {
	for _, marker := range ppidGatherForbiddenMarkers {
		if strings.Contains(gather, marker) {
			return fmt.Errorf("gatherStr contains incompatible pattern %q", marker)
		}
	}
	for _, marker := range ppidGatherRequiredMarkers {
		if !strings.Contains(gather, marker) {
			return fmt.Errorf("gatherStr missing required pattern %q", marker)
		}
	}
	return nil
}
