package techs

import "testing"

func TestID(t *testing.T) {
	tests := []struct {
		tech Tech
		want string
	}{
		{tech: L1002{}, want: "L1002"},
		{tech: T1098{}, want: "T1098"},
		{tech: L1001{}, want: "L1001"},
	}

	for _, tt := range tests {
		if got := ID(tt.tech); got != tt.want {
			t.Fatalf("ID(%T) = %q, want %q", tt.tech, got, tt.want)
		}
	}
}
