package events

import "testing"

func ppidValueCases() []struct {
	name string
	ppid uint32
} {
	return []struct {
		name string
		ppid uint32
	}{
		{"zero_orphan", 0},
		{"init", 1},
		{"typical_shell_child", 4242},
		{"max_uint16", 65535},
		{"large_pid", 1048576},
		{"max_uint32", ^uint32(0)},
	}
}

func TestFetchPpidReturnsStoredValue(t *testing.T) {
	for _, tt := range ppidValueCases() {
		t.Run(tt.name, func(t *testing.T) {
			base := &eventBase{Ppid: tt.ppid}
			if got := base.FetchPpid(); got != tt.ppid {
				t.Fatalf("FetchPpid() = %d, want %d", got, tt.ppid)
			}
		})
	}
}

func TestEventBaseWriteRoundTripPpid(t *testing.T) {
	for _, tt := range ppidValueCases() {
		t.Run(tt.name, func(t *testing.T) {
			original := &eventBase{
				Uid:  1000,
				Pid:  2000,
				Ppid: tt.ppid,
				Ret:  eventNormal,
			}
			data := encodeEvent(t, original)
			ev, err := (&eventBase{}).Write(data)
			if err != nil {
				t.Fatalf("Write() error: %v", err)
			}
			written := ev.(*eventBase)
			if written.FetchPpid() != tt.ppid {
				t.Fatalf("FetchPpid() = %d, want %d", written.FetchPpid(), tt.ppid)
			}
			if written.FetchPid() != original.Pid {
				t.Fatalf("FetchPid() = %d, want %d", written.FetchPid(), original.Pid)
			}
		})
	}
}

func TestExecWritePreservesPpid(t *testing.T) {
	for _, tt := range ppidValueCases() {
		t.Run(tt.name, func(t *testing.T) {
			original := &Exec{}
			original.Ppid = tt.ppid
			original.Pid = 9000

			data := encodeEvent(t, original)
			ev, err := (&Exec{}).Write(data)
			if err != nil {
				t.Fatalf("Exec.Write() error: %v", err)
			}
			if got := ev.(*Exec).FetchPpid(); got != tt.ppid {
				t.Fatalf("FetchPpid() = %d, want %d", got, tt.ppid)
			}
		})
	}
}

func TestOpenWritePreservesPpid(t *testing.T) {
	for _, tt := range ppidValueCases() {
		t.Run(tt.name, func(t *testing.T) {
			original := &Open{}
			original.Ppid = tt.ppid
			original.Pid = 9001

			data := encodeEvent(t, original)
			ev, err := (&Open{}).Write(data)
			if err != nil {
				t.Fatalf("Open.Write() error: %v", err)
			}
			if got := ev.(*Open).FetchPpid(); got != tt.ppid {
				t.Fatalf("FetchPpid() = %d, want %d", got, tt.ppid)
			}
		})
	}
}

func TestListenWritePreservesPpid(t *testing.T) {
	for _, tt := range ppidValueCases() {
		t.Run(tt.name, func(t *testing.T) {
			original := &Listen{}
			original.Ppid = tt.ppid
			original.Pid = 9002

			data := encodeEvent(t, original)
			ev, err := (&Listen{}).Write(data)
			if err != nil {
				t.Fatalf("Listen.Write() error: %v", err)
			}
			if got := ev.(*Listen).FetchPpid(); got != tt.ppid {
				t.Fatalf("FetchPpid() = %d, want %d", got, tt.ppid)
			}
		})
	}
}

func TestReadlineWritePreservesPpid(t *testing.T) {
	for _, tt := range ppidValueCases() {
		t.Run(tt.name, func(t *testing.T) {
			original := &Readline{}
			original.Ppid = tt.ppid
			original.Pid = 9003

			data := encodeEvent(t, original)
			ev, err := (&Readline{}).Write(data)
			if err != nil {
				t.Fatalf("Readline.Write() error: %v", err)
			}
			if got := ev.(*Readline).FetchPpid(); got != tt.ppid {
				t.Fatalf("FetchPpid() = %d, want %d", got, tt.ppid)
			}
		})
	}
}
