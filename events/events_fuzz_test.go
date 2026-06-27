package events

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzCStr(f *testing.F) {
	f.Add([]byte("normal\x00string"))
	f.Add([]byte{0x00})
	f.Add([]byte{})
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = CStr(data)
	})
}

func encodeEventData(ev interface{}) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, ev)
	return buf.Bytes()
}

func FuzzWriteEventData(f *testing.F) {
	f.Add(byte(0), []byte{})
	f.Add(byte(0), encodeEventData(&Exec{}))
	f.Add(byte(1), []byte{})
	f.Add(byte(1), encodeEventData(&Listen{}))
	f.Add(byte(2), []byte{})
	f.Add(byte(2), encodeEventData(&Open{}))
	f.Add(byte(3), []byte{})
	f.Add(byte(3), encodeEventData(&Readline{}))
	f.Add(byte(0), make([]byte, 512))

	f.Fuzz(func(t *testing.T, kind byte, data []byte) {
		var ev Event
		switch kind % 4 {
		case 0:
			ev = &Exec{}
		case 1:
			ev = &Listen{}
		case 2:
			ev = &Open{}
		default:
			ev = &Readline{}
		}
		_, _ = WriteEventData(ev, data)
	})
}
