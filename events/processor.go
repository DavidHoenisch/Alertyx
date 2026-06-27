package events

import "strings"

// EventProcessor merges eBPF event fragments (pwd, argv, return) into complete events.
type EventProcessor struct {
	pwdCache   map[uint32][]string
	otherCache map[uint32][]interface{}
	eventCache map[uint32]Event
}

func NewEventProcessor() *EventProcessor {
	return &EventProcessor{
		pwdCache:   make(map[uint32][]string),
		otherCache: make(map[uint32][]interface{}),
		eventCache: make(map[uint32]Event),
	}
}

func joinPwdSegments(segments []string) string {
	tmp := strings.Join(segments, "/")
	if tmp == "" {
		return tmp
	}
	if tmp[0] != '/' {
		tmp = "/" + tmp
	}
	tmp = strings.Replace(tmp, "\n", "\\n", -1)
	tmp = strings.TrimSpace(tmp)
	if len(tmp) >= 128 {
		tmp = tmp[:124] + "..."
	}
	return tmp
}

// Process handles one decoded event. The second return value is true when the event is
// ready to be emitted to downstream consumers.
func (p *EventProcessor) Process(event Event) (Event, bool) {
	if event.IsRet() {
		caEvent, ok := p.eventCache[event.FetchPid()]
		if ok {
			caEvent.SetRetVal(event.FetchRetVal())
			switch event.(type) {
			case *Exec:
				tmpEventNew := event.(*Exec)
				tmpEventOld := caEvent.(*Exec)
				tmpEventOld.Comm = tmpEventNew.Comm
				caEvent = tmpEventOld
			}
			event = caEvent
		}
		if pwdVal, ok := p.pwdCache[event.FetchPid()]; ok {
			event.SetPwd(joinPwdSegments(pwdVal))
			delete(p.pwdCache, event.FetchPid())
		}
		if otherVal, ok := p.otherCache[event.FetchPid()]; ok {
			event.SetOther(otherVal)
			delete(p.otherCache, event.FetchPid())
		}
		delete(p.eventCache, event.FetchPid())
		return event, true
	}

	if event.IsPwd() {
		pwdItems, ok := p.pwdCache[event.FetchPid()]
		if !ok {
			pwdItems = make([]string, 0)
		}
		p.pwdCache[event.FetchPid()] = append([]string{event.FetchPwd()}, pwdItems...)
		return nil, false
	}

	if event.IsOther() {
		otherItems, ok := p.otherCache[event.FetchPid()]
		if !ok {
			otherItems = make([]interface{}, 0)
		}
		p.otherCache[event.FetchPid()] = append([]interface{}{event.FetchOther()}, otherItems...)
		return nil, false
	}

	p.eventCache[event.FetchPid()] = event
	return nil, false
}
