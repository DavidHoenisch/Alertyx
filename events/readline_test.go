package events

import "testing"

func TestReadlinePrint(t *testing.T) {
	ev := &Readline{}
	copyCString(ev.Str[:], "sudo -i")

	got := ev.Print()
	want := "sudo -i"
	if got != want {
		t.Fatalf("Print() = %q, want %q", got, want)
	}
}
