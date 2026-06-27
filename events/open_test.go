package events

import (
	"strings"
	"testing"
)

func TestOpenPrint(t *testing.T) {
	ev := &Open{
		eventBase: eventBase{},
		Dfd:       3,
		Flags:     0o644,
	}
	copyCString(ev.Filename[:], "secrets.txt")
	copyCString(ev.Pwd[:], "/tmp")

	got := ev.Print()
	if !strings.Contains(got, "secrets.txt") {
		t.Fatalf("Print() = %q, expected filename", got)
	}
	if !strings.Contains(got, "/tmp") {
		t.Fatalf("Print() = %q, expected pwd", got)
	}
	if !strings.Contains(got, "flags 420") {
		t.Fatalf("Print() = %q, expected flags", got)
	}
}

func TestOpenPrintEmptyFields(t *testing.T) {
	ev := &Open{Flags: 1}
	got := ev.Print()
	if got[0] != '?' {
		t.Fatalf("Print() should use ? for empty filename, got %q", got)
	}
}
