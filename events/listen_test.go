package events

import "testing"

func TestListenPrint(t *testing.T) {
	ev := Listen{
		Addr: 0x0100007f,
		Port: 443,
	}
	got := ev.Print()
	want := "Addr 16777343, Port 443"
	if got != want {
		t.Fatalf("Print() = %q, want %q", got, want)
	}
}
