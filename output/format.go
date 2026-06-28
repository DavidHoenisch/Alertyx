package output

import "fmt"

const (
	FormatText = "text"
	FormatJSON = "json"
)

// Format selects human-readable text or structured JSON output.
var Format = FormatText

// SetFormat validates and stores the output format name.
func SetFormat(name string) error {
	switch name {
	case FormatText, FormatJSON:
		Format = name
		return nil
	default:
		return fmt.Errorf("invalid output format %q (valid: %s, %s)", name, FormatText, FormatJSON)
	}
}

// IsJSON reports whether detections and events are emitted as NDJSON.
func IsJSON() bool {
	return Format == FormatJSON
}
