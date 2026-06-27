// Package events provides event structures and data through eBPF.
package events

import (
	"bytes"
	"container/ring"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/iovisor/gobpf/bcc"
)

type Ctx struct {
	LoadWg *sync.WaitGroup
	Load   chan string
	Error  chan string
	Quit   chan bool
}

// Event is an interface that represents an event object.
type Event interface {
	Print() string
	Write([]byte) (Event, error)
	FetchUid() uint32
	FetchPid() uint32
	FetchPpid() uint32
	FetchPwd() string
	FetchRetVal() int32
	FetchOther() interface{}
	IsRet() bool
	IsPwd() bool
	IsOther() bool
	SetPwd(string)
	SetRetVal(int32)
	SetOther([]interface{})
}

type eventBase struct {
	Uid    uint32
	Pid    uint32
	Ppid   uint32
	RetVal int32
	Ret    int32
	Pwd    [128]byte
}

type LogItem struct {
	Time time.Time
	Ev   Event
}

const (
	EventKindNormal = iota
	EventKindPwd
	EventKindRet
	EventKindOther
)

const (
	eventNormal = EventKindNormal
	eventPwd    = EventKindPwd
	eventRet    = EventKindRet
	eventOther  = EventKindOther
)

func (e *eventBase) Print() string {
	return "eventBase"
}

func (e *eventBase) FetchUid() uint32 {
	return e.Uid
}

func (e *eventBase) FetchPid() uint32 {
	return e.Pid
}

func (e *eventBase) FetchPpid() uint32 {
	return e.Ppid
}

func (e *eventBase) IsRet() bool {
	return e.Ret == eventRet
}

func (e *eventBase) IsPwd() bool {
	return e.Ret == eventPwd
}

func (e *eventBase) IsOther() bool {
	return e.Ret == eventOther
}

func (e *eventBase) FetchRetVal() int32 {
	return e.RetVal
}

func (e *eventBase) SetRetVal(val int32) {
	e.RetVal = val
}

func (e *eventBase) Write(data []byte) (Event, error) {
	newEvent := &eventBase{}
	err := binary.Read(bytes.NewBuffer(data), bcc.GetHostByteOrder(), newEvent)
	return newEvent, err
}

func (e *eventBase) FetchPwd() string {
	pwd := CStr(e.Pwd[:])
	if pwd == "" {
		return "?"
	}
	return pwd
}

func (e *eventBase) FetchOther() interface{} {
	return nil
}

func (e *eventBase) SetPwd(tmp string) {
	for i := range tmp {
		e.Pwd[i] = tmp[i]
	}
}

func (e *eventBase) SetOther(input []interface{}) {}

// Contains the most recent 1000 events
var EventLog = ring.New(1000)

// logEvent writes the given event to the EventLog.
func Log(e Event) {
	EventLog.Value = LogItem{
		Time: time.Now(),
		Ev:   e,
	}
	EventLog = EventLog.Next()
}

func GetAll() []LogItem {
	allEvents := []LogItem{}
	EventLog.Do(func(e interface{}) {
		if reflect.TypeOf(e) == reflect.TypeOf(LogItem{}) {
			allEvents = append(allEvents, e.(LogItem))
		}
	})
	return allEvents
}

func NewContext() Ctx {
	return Ctx{
		LoadWg: &sync.WaitGroup{},
		Load:   make(chan string),
		Error:  make(chan string),
		Quit:   make(chan bool),
	}
}

func TypeHeader(e Event) string {
	return strings.Split(fmt.Sprintf("%T", e), ".")[1]
}

func CStr(cString []byte) string {
	if len(cString) == 0 {
		return ""
	}
	byteIndex := bytes.IndexByte(cString, 0)
	if byteIndex == -1 {
		return string(cString[:]) + "..."
	}
	return string(cString[:byteIndex])
}

func FormatError(eventType, errorMsg string, err error) string {
	return eventType + ": " + errorMsg + ": " + err.Error()
}
