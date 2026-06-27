package events

import "testing"

func TestWriteEventDataExec(t *testing.T) {
	original := &Exec{}
	copyCString(original.Comm[:], "sh")
	copyCString(original.Argv[:], "-c ls")
	original.Uid = 1000
	original.Pid = 1234
	original.Ppid = 1

	data := encodeEvent(t, original)
	ev, err := (&Exec{}).Write(data)
	if err != nil {
		t.Fatalf("Exec.Write() error: %v", err)
	}
	written := ev.(*Exec)
	if CStr(written.Comm[:]) != "sh" {
		t.Fatalf("Comm = %q", CStr(written.Comm[:]))
	}
	if CStr(written.Argv[:]) != "-c ls" {
		t.Fatalf("Argv = %q", CStr(written.Argv[:]))
	}
	if written.FetchPid() != 1234 {
		t.Fatalf("Pid = %d", written.FetchPid())
	}
}

func TestWriteEventDataListen(t *testing.T) {
	original := &Listen{}
	original.Addr = 0x7f000001
	original.Port = 8080
	original.SockType = 1
	original.Backlog = 128

	data := encodeEvent(t, original)
	ev, err := (&Listen{}).Write(data)
	if err != nil {
		t.Fatalf("Listen.Write() error: %v", err)
	}
	written := ev.(*Listen)
	if written.Addr != original.Addr || written.Port != original.Port {
		t.Fatalf("Listen fields mismatch: addr=%d port=%d", written.Addr, written.Port)
	}
}

func TestWriteEventDataOpen(t *testing.T) {
	original := &Open{}
	original.Dfd = -100
	original.Flags = 0o644
	copyCString(original.Filename[:], "/etc/passwd")
	copyCString(original.Pwd[:], "/")

	data := encodeEvent(t, original)
	ev, err := (&Open{}).Write(data)
	if err != nil {
		t.Fatalf("Open.Write() error: %v", err)
	}
	written := ev.(*Open)
	if CStr(written.Filename[:]) != "/etc/passwd" {
		t.Fatalf("Filename = %q", CStr(written.Filename[:]))
	}
	if written.Flags != 0o644 {
		t.Fatalf("Flags = %d", written.Flags)
	}
}

func TestWriteEventDataReadline(t *testing.T) {
	original := &Readline{}
	copyCString(original.Str[:], "whoami")

	data := encodeEvent(t, original)
	ev, err := (&Readline{}).Write(data)
	if err != nil {
		t.Fatalf("Readline.Write() error: %v", err)
	}
	written := ev.(*Readline)
	if CStr(written.Str[:]) != "whoami" {
		t.Fatalf("Str = %q", CStr(written.Str[:]))
	}
}

func TestWriteEventDataInvalidBuffer(t *testing.T) {
	_, err := WriteEventData(&Exec{}, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("WriteEventData() expected error for short buffer")
	}
}
