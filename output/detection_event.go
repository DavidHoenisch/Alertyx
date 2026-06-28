package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/DavidHoenisch/Alertyx/techs"
)

// DetectionEvent is a structured detection record for SIEM integration.
type DetectionEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Technique   string    `json:"technique"`
	TechniqueID string    `json:"technique_id"`
	Severity    string    `json:"severity"`
	Process     string    `json:"process"`
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	UID         uint32    `json:"uid"`
	Username    string    `json:"username"`
	PWD         string    `json:"pwd"`
	Details     string    `json:"details"`
	Artifacts   []string  `json:"artifacts"`
}

var jsonWriter io.Writer = os.Stdout

// SetJSONWriter redirects NDJSON output. Intended for tests.
func SetJSONWriter(w io.Writer) {
	if w == nil {
		jsonWriter = os.Stdout
		return
	}
	jsonWriter = w
}

// SeverityFromLevel maps detection levels to SIEM severity strings.
func SeverityFromLevel(level int) string {
	switch level {
	case techs.LevelCrit:
		return "crit"
	case techs.LevelErr:
		return "err"
	case techs.LevelWarn:
		return "warn"
	default:
		return "info"
	}
}

// WriteDetectionEvent writes one compact JSON object followed by a newline (NDJSON).
func WriteDetectionEvent(evt DetectionEvent) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal detection event: %w", err)
	}
	_, err = fmt.Fprintf(jsonWriter, "%s\n", data)
	return err
}
