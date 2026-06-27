package events

import "testing"

func FuzzCStr(f *testing.F) {
	f.Add([]byte("normal\x00string"))
	f.Add([]byte{0x00})
	f.Add([]byte{})
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = CStr(data)
	})
}
