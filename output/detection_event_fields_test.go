package output

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

var detectionEventJSONFields = []string{
	"timestamp",
	"technique",
	"technique_id",
	"severity",
	"process",
	"pid",
	"ppid",
	"uid",
	"username",
	"pwd",
	"details",
	"artifacts",
}

func TestDetectionEventStructIncludesAllJSONFields(t *testing.T) {
	typ := reflect.TypeOf(DetectionEvent{})
	tags := make(map[string]struct{}, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		tags[tag] = struct{}{}
	}

	for _, want := range detectionEventJSONFields {
		if _, ok := tags[want]; !ok {
			t.Fatalf("DetectionEvent missing json field %q", want)
		}
	}
}

func TestWriteDetectionEventIncludesAllJSONFields(t *testing.T) {
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
		PPID:        1,
		UID:         1000,
		Username:    "attacker",
		PWD:         "/home/attacker",
		Details:     "/etc/shadow path /home/attacker flags 0",
		Artifacts:   []string{"/etc/shadow path /home/attacker flags 0"},
	}

	if err := WriteDetectionEvent(evt); err != nil {
		t.Fatalf("WriteDetectionEvent() error = %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	for _, key := range detectionEventJSONFields {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("NDJSON missing field %q in %v", key, decoded)
		}
	}

	if decoded["technique_id"] != "L1002" {
		t.Fatalf("technique_id = %v, want L1002", decoded["technique_id"])
	}
	if decoded["process"] != "cat" {
		t.Fatalf("process = %v, want cat", decoded["process"])
	}
	if decoded["username"] != "attacker" {
		t.Fatalf("username = %v, want attacker", decoded["username"])
	}
}
