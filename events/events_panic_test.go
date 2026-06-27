package events

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"
)

func assertNoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", name, r)
		}
	}()
	fn()
}

func TestCStrNoPanic(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"lone null", []byte{0x00}},
		{"no null terminator", make([]byte, 4096)},
		{"high bytes", []byte{0xff, 0xfe, 0xfd, 0x00, 0x41}},
		{"embedded nulls", []byte("a\x00b\x00c")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertNoPanic(t, "CStr", func() {
				_ = CStr(tc.data)
			})
		})
	}
}

func TestWriteEventDataNoPanic(t *testing.T) {
	malformed := [][]byte{
		nil,
		{},
		{0xff},
		make([]byte, 1),
		make([]byte, 512),
		make([]byte, 4096),
	}
	events := []Event{
		&Exec{},
		&Listen{},
		&Open{},
		&Readline{},
	}
	for _, ev := range events {
		name := TypeHeader(ev)
		for i, data := range malformed {
			t.Run("case"+strconv.Itoa(i), func(t *testing.T) {
				assertNoPanic(t, "WriteEventData", func() {
					_, _ = WriteEventData(ev, data)
				})
			})
		}
		t.Run(name+"/truncated struct", func(t *testing.T) {
			buf := new(bytes.Buffer)
			_ = binary.Write(buf, binary.LittleEndian, ev)
			truncated := buf.Bytes()[:len(buf.Bytes())/2]
			assertNoPanic(t, "WriteEventData", func() {
				_, _ = WriteEventData(ev, truncated)
			})
		})
	}
}
