// Package events Exec provides data on execve calls.
package events

import (
	"fmt"
	"strings"
)

const (
	argSize = 128
	commLen = 16
)

type Exec struct {
	eventBase
	Comm [commLen]byte
	Argv [argSize]byte
}

func (e *Exec) Print() string {
	return fmt.Sprintf("%s -> %s", CStr(e.Comm[:]), CStr(e.Argv[:]))
}

func (e *Exec) FetchOther() interface{} {
	return e.Argv
}

func (e *Exec) SetOther(args []interface{}) {
	tmp := ""
	for i := range args {
		tmpRaw := args[i].([128]uint8)
		tmp = CStr(tmpRaw[:]) + " " + tmp
	}
	tmp = strings.Replace(tmp, "\n", "\\n", -1)
	tmp = strings.TrimSpace(tmp)
	if len(tmp) > 128 {
		tmp = tmp[:127]
	}
	for i := range tmp {
		e.Argv[i] = tmp[i]
	}
	e.Argv[len(tmp)] = '\x00'
}
