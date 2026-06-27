package events

import (
	"bytes"
	"container/ring"
	"encoding/binary"
	"errors"
	"testing"
)

func encodeEvent(t *testing.T, v interface{}) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return buf.Bytes()
}

func copyCString(dst []byte, s string) {
	copy(dst, s)
	if len(s) < len(dst) {
		dst[len(s)] = 0
	}
}

func TestCStr(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty slice", []byte{}, ""},
		{"null terminated", []byte("hello\x00world"), "hello"},
		{"no null terminator", []byte("hello"), "hello..."},
		{"single null", []byte{0}, ""},
		{"embedded null only prefix", []byte{'a', 0, 'b'}, "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CStr(tt.in); got != tt.want {
				t.Fatalf("CStr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEventBaseMethods(t *testing.T) {
	base := &eventBase{
		Uid:    1000,
		Pid:    4242,
		Ppid:   1,
		RetVal: 0,
		Ret:    eventNormal,
	}
	copyCString(base.Pwd[:], "/home/user")

	if base.Print() != "eventBase" {
		t.Fatalf("Print() = %q", base.Print())
	}
	if base.FetchUid() != 1000 {
		t.Fatalf("FetchUid() = %d", base.FetchUid())
	}
	if base.FetchPid() != 4242 {
		t.Fatalf("FetchPid() = %d", base.FetchPid())
	}
	if base.FetchPpid() != 1 {
		t.Fatalf("FetchPpid() = %d", base.FetchPpid())
	}
	if base.IsRet() || base.IsPwd() || base.IsOther() {
		t.Fatal("expected normal event flags to be false")
	}
	if base.FetchRetVal() != 0 {
		t.Fatalf("FetchRetVal() = %d", base.FetchRetVal())
	}
	if base.FetchPwd() != "/home/user" {
		t.Fatalf("FetchPwd() = %q", base.FetchPwd())
	}
	if base.FetchOther() != nil {
		t.Fatal("FetchOther() should be nil for eventBase")
	}

	base.SetRetVal(42)
	if base.FetchRetVal() != 42 {
		t.Fatalf("SetRetVal() = %d", base.FetchRetVal())
	}

	base.Ret = eventRet
	if !base.IsRet() {
		t.Fatal("expected IsRet() true")
	}
	base.Ret = eventPwd
	if !base.IsPwd() {
		t.Fatal("expected IsPwd() true")
	}
	base.Ret = eventOther
	if !base.IsOther() {
		t.Fatal("expected IsOther() true")
	}
}

func TestEventBaseSetPwd(t *testing.T) {
	base := &eventBase{}
	base.SetPwd("/tmp")
	if base.FetchPwd() != "/tmp" {
		t.Fatalf("SetPwd() = %q", base.FetchPwd())
	}
}

func TestEventBaseSetOther(t *testing.T) {
	base := &eventBase{}
	base.SetOther([]interface{}{"ignored"})
}

func TestEventBaseFetchPwdEmpty(t *testing.T) {
	base := &eventBase{}
	if base.FetchPwd() != "?" {
		t.Fatalf("FetchPwd() on empty pwd = %q, want ?", base.FetchPwd())
	}
}

func TestEventBaseWrite(t *testing.T) {
	original := &eventBase{
		Uid:    500,
		Pid:    600,
		Ppid:   700,
		RetVal: -1,
		Ret:    eventRet,
	}
	copyCString(original.Pwd[:], "/var/log")

	data := encodeEvent(t, original)
	ev, err := (&eventBase{}).Write(data)
	if err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	written := ev.(*eventBase)
	if written.Uid != original.Uid || written.Pid != original.Pid || written.Ppid != original.Ppid {
		t.Fatalf("Write() uid/pid/ppid mismatch: %+v", written)
	}
	if written.RetVal != original.RetVal || written.Ret != original.Ret {
		t.Fatalf("Write() ret fields mismatch: %+v", written)
	}
	if CStr(written.Pwd[:]) != "/var/log" {
		t.Fatalf("Write() pwd = %q", CStr(written.Pwd[:]))
	}
}

func TestLogAndGetAll(t *testing.T) {
	original := EventLog
	t.Cleanup(func() { EventLog = original })

	EventLog = ring.New(3)
	ev := &Exec{}
	copyCString(ev.Comm[:], "bash")

	Log(ev)
	Log(ev)
	items := GetAll()
	if len(items) != 2 {
		t.Fatalf("GetAll() len = %d, want 2", len(items))
	}
	if items[0].Ev == nil || items[1].Ev == nil {
		t.Fatal("GetAll() returned nil events")
	}
}

func TestNewContext(t *testing.T) {
	ctx := NewContext()
	if ctx.LoadWg == nil || ctx.Load == nil || ctx.Error == nil || ctx.Quit == nil {
		t.Fatal("NewContext() returned incomplete Ctx")
	}
}

func TestTypeHeader(t *testing.T) {
	ev := &Open{}
	if got := TypeHeader(ev); got != "Open" {
		t.Fatalf("TypeHeader() = %q, want Open", got)
	}
}

func TestNewError(t *testing.T) {
	msg := FormatError("open", "attach failed", errors.New("permission denied"))
	if msg != "open: attach failed: permission denied" {
		t.Fatalf("newError() = %q", msg)
	}
}
