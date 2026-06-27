package events

import "testing"

func TestJoinPwdSegments(t *testing.T) {
	tests := []struct {
		name     string
		segments []string
		want     string
	}{
		{"empty", []string{}, ""},
		{"single relative", []string{"tmp"}, "/tmp"},
		{"multiple", []string{"var", "log"}, "/var/log"},
		{"already absolute", []string{"/etc"}, "/etc"},
		{"escapes newline", []string{"a\nb"}, "/a\\nb"},
		{"truncates long path", []string{string(make([]byte, 200))}, string(make([]byte, 124)) + "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinPwdSegments(tt.segments)
			if tt.name == "truncates long path" {
				if len(got) != 127 {
					t.Fatalf("joinPwdSegments() len = %d, want 127", len(got))
				}
				return
			}
			if got != tt.want {
				t.Fatalf("joinPwdSegments() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEventProcessorCachesNormalEvent(t *testing.T) {
	p := NewEventProcessor()
	ev := &Open{eventBase: eventBase{Pid: 99, Ret: eventNormal}}
	ready, ok := p.Process(ev)
	if ok || ready != nil {
		t.Fatal("normal event should be cached, not emitted")
	}
}

func TestEventProcessorReturnWithoutCache(t *testing.T) {
	p := NewEventProcessor()
	ev := &Open{eventBase: eventBase{Pid: 99, Ret: eventRet, RetVal: 0}}
	ready, ok := p.Process(ev)
	if !ok || ready == nil {
		t.Fatal("return event should be emitted even without cache")
	}
}

func TestEventProcessorReturnMergesCachedEvent(t *testing.T) {
	p := NewEventProcessor()
	cached := &Exec{eventBase: eventBase{Pid: 42, Ret: eventNormal}}
	cachedRet := &Exec{eventBase: eventBase{Pid: 42, Ret: eventRet, RetVal: 7}}
	copyCString(cachedRet.Comm[:], "bash")

	p.Process(cached)
	ready, ok := p.Process(cachedRet)
	if !ok {
		t.Fatal("expected ready event")
	}
	got := ready.(*Exec)
	if got.FetchRetVal() != 7 {
		t.Fatalf("RetVal = %d", got.FetchRetVal())
	}
	if CStr(got.Comm[:]) != "bash" {
		t.Fatalf("Comm = %q", CStr(got.Comm[:]))
	}
}

func TestEventProcessorPwdAndReturn(t *testing.T) {
	p := NewEventProcessor()
	openEv := &Open{eventBase: eventBase{Pid: 5, Ret: eventNormal}}
	pwdEv := &Open{eventBase: eventBase{Pid: 5, Ret: eventPwd}}
	copyCString(pwdEv.Pwd[:], "etc")
	retEv := &Open{eventBase: eventBase{Pid: 5, Ret: eventRet, RetVal: 3}}
	copyCString(pwdEv.Pwd[:], "etc")

	p.Process(openEv)
	p.Process(pwdEv)
	ready, ok := p.Process(retEv)
	if !ok {
		t.Fatal("expected ready event")
	}
	if ready.FetchPwd() != "/etc" {
		t.Fatalf("FetchPwd() = %q", ready.FetchPwd())
	}
}

func TestEventProcessorOtherAndReturn(t *testing.T) {
	p := NewEventProcessor()
	execEv := &Exec{eventBase: eventBase{Pid: 8, Ret: eventNormal}}
	otherEv := &Exec{eventBase: eventBase{Pid: 8, Ret: eventOther}}
	copyCString(otherEv.Argv[:], "-la")
	retEv := &Exec{eventBase: eventBase{Pid: 8, Ret: eventRet, RetVal: 0}}

	p.Process(execEv)
	p.Process(otherEv)
	ready, ok := p.Process(retEv)
	if !ok {
		t.Fatal("expected ready event")
	}
	got := ready.(*Exec)
	if CStr(got.Argv[:]) != "-la" {
		t.Fatalf("Argv = %q", CStr(got.Argv[:]))
	}
}
