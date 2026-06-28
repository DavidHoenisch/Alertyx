package events

import "testing"

func TestProcessSampleMergesExecReturn(t *testing.T) {
	p := NewEventProcessor()
	template := &Exec{}

	enter := &Exec{eventBase: eventBase{Pid: 42, Ret: eventNormal}}
	enterData := encodeEvent(t, enter)
	if _, ok, err := ProcessSample(p, template, enterData); err != nil || ok {
		t.Fatalf("enter sample: ok=%v err=%v", ok, err)
	}

	ret := &Exec{eventBase: eventBase{Pid: 42, Ret: eventRet, RetVal: 0}}
	copyCString(ret.Comm[:], "true")
	retData := encodeEvent(t, ret)
	ready, ok, err := ProcessSample(p, template, retData)
	if err != nil || !ok {
		t.Fatalf("return sample: ok=%v err=%v", ok, err)
	}
	got := ready.(*Exec)
	if got.FetchRetVal() != 0 {
		t.Fatalf("RetVal = %d", got.FetchRetVal())
	}
	if CStr(got.Comm[:]) != "true" {
		t.Fatalf("Comm = %q", CStr(got.Comm[:]))
	}
}

func TestProcessSampleInvalidData(t *testing.T) {
	p := NewEventProcessor()
	_, ok, err := ProcessSample(p, &Open{}, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected decode error for truncated sample")
	}
	if ok {
		t.Fatal("expected ok=false on decode error")
	}
}
