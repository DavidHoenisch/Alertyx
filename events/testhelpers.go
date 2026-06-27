package events

// Test helpers for constructing events in unit tests across packages.

func NewListen(uid, pid uint32) *Listen {
	return &Listen{
		eventBase: eventBase{Uid: uid, Pid: pid},
	}
}

func NewOpen(uid, pid uint32, filename string, flags int32, pwd string, retVal int32) *Open {
	o := &Open{
		eventBase: eventBase{Uid: uid, Pid: pid, RetVal: retVal},
		Flags:     flags,
	}
	copy(o.Filename[:], filename)
	copy(o.Pwd[:], pwd)
	return o
}

func NewExec(uid, pid uint32, argv string) *Exec {
	e := &Exec{
		eventBase: eventBase{Uid: uid, Pid: pid},
	}
	copy(e.Argv[:], argv)
	return e
}

func SetFilename(o *Open, filename string) {
	copy(o.Filename[:], filename)
}

func SetPwd(o *Open, pwd string) {
	copy(o.Pwd[:], pwd)
}
