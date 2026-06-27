package events

import "fmt"

type Listen struct {
	eventBase
	Addr     uint32
	Port     uint16
	SockType int16
	Backlog  int32
}

func (e Listen) Print() string {
	return fmt.Sprintf("Addr %d, Port %d", e.Addr, e.Port)
}
