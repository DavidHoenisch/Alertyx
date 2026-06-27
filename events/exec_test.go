package events

import "testing"

func TestExecPrint(t *testing.T) {
	ev := &Exec{}
	copyCString(ev.Comm[:], "curl")
	copyCString(ev.Argv[:], "http://example.com")

	got := ev.Print()
	want := "curl -> http://example.com"
	if got != want {
		t.Fatalf("Print() = %q, want %q", got, want)
	}
}

func TestExecFetchOther(t *testing.T) {
	ev := &Exec{}
	copyCString(ev.Argv[:], "arg1 arg2")
	if ev.FetchOther() != ev.Argv {
		t.Fatal("FetchOther() should return Argv field")
	}
}

func TestExecSetOther(t *testing.T) {
	ev := &Exec{}
	arg1 := [128]uint8{}
	arg2 := [128]uint8{}
	copyCString(arg1[:], "ls")
	copyCString(arg2[:], "-la")

	ev.SetOther([]interface{}{arg1, arg2})
	got := CStr(ev.Argv[:])
	if got != "-la ls" {
		t.Fatalf("SetOther() Argv = %q, want %q", got, "-la ls")
	}
}

func TestExecSetOtherTruncatesLongArgs(t *testing.T) {
	ev := &Exec{}
	long := [128]uint8{}
	copy(long[:], string(make([]byte, 200)))

	ev.SetOther([]interface{}{long})
	if len(CStr(ev.Argv[:])) > 127 {
		t.Fatalf("SetOther() should truncate argv to 127 chars, got len %d", len(CStr(ev.Argv[:])))
	}
}

func TestExecSetOtherEscapesNewlines(t *testing.T) {
	ev := &Exec{}
	arg := [128]uint8{}
	copyCString(arg[:], "line1\nline2")

	ev.SetOther([]interface{}{arg})
	if CStr(ev.Argv[:]) != "line1\\nline2" {
		t.Fatalf("SetOther() = %q, want escaped newlines", CStr(ev.Argv[:]))
	}
}
