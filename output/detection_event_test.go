package output

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DavidHoenisch/Alertyx/techs"
)

func TestWriteDetectionEventNDJSON(t *testing.T) {
	t.Cleanup(func() { SetJSONWriter(os.Stdout) })

	var buf bytes.Buffer
	SetJSONWriter(&buf)

	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	evt := DetectionEvent{
		Timestamp:   ts,
		Technique:   "Suspicious /etc/shadow Access",
		TechniqueID: "L1002",
		Severity:    "warn",
		Process:     "cat",
		PID:         12345,
		UID:         1000,
		Username:    "attacker",
		PWD:         "/home/attacker",
		Details:     "attacker in /home/attacker",
		Artifacts:   []string{"/etc/shadow path /home/attacker flags 0"},
	}

	if err := WriteDetectionEvent(evt); err != nil {
		t.Fatalf("WriteDetectionEvent() error = %v", err)
	}

	line := strings.TrimSpace(buf.String())
	if strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("expected exactly one trailing newline, got %q", buf.String())
	}
	if strings.Contains(line, "\n") {
		t.Fatalf("expected single-line JSON object, got %q", line)
	}

	var decoded DetectionEvent
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded.TechniqueID != "L1002" {
		t.Fatalf("technique_id = %q, want L1002", decoded.TechniqueID)
	}
	if decoded.Severity != "warn" {
		t.Fatalf("severity = %q, want warn", decoded.Severity)
	}
}

func TestWriteDetectionEventMultipleLines(t *testing.T) {
	t.Cleanup(func() { SetJSONWriter(os.Stdout) })

	var buf bytes.Buffer
	SetJSONWriter(&buf)

	events := []DetectionEvent{
		{Technique: "first", TechniqueID: "L1001", Severity: "warn"},
		{Technique: "second", TechniqueID: "L1002", Severity: "err"},
	}

	for _, evt := range events {
		if err := WriteDetectionEvent(evt); err != nil {
			t.Fatalf("WriteDetectionEvent() error = %v", err)
		}
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d NDJSON lines, want 2", len(lines))
	}
	for i, line := range lines {
		var decoded DetectionEvent
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i, err)
		}
	}
}

func TestSeverityFromLevel(t *testing.T) {
	tests := []struct {
		level int
		want  string
	}{
		{level: techs.LevelWarn, want: "warn"},
		{level: techs.LevelErr, want: "err"},
		{level: techs.LevelCrit, want: "crit"},
		{level: techs.LevelNil, want: "info"},
	}

	for _, tt := range tests {
		if got := SeverityFromLevel(tt.level); got != tt.want {
			t.Fatalf("SeverityFromLevel(%d) = %q, want %q", tt.level, got, tt.want)
		}
	}
}
