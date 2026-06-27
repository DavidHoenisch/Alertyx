package events

import "fmt"

const fileNameSize = 80

type Open struct {
	eventBase
	Dfd      int16
	Filename [fileNameSize]byte
	Flags    int32
}

func (e *Open) Print() string {
	if CStr(e.Filename[:]) == "" {
		e.Filename[0] = '?'
	}
	if CStr(e.Pwd[:]) == "" {
		e.Pwd[0] = '?'
	}
	return fmt.Sprintf("%s path %s flags %d", e.Filename, e.Pwd, e.Flags)
}
