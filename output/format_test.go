package output

import "testing"

func TestSetFormat(t *testing.T) {
	t.Cleanup(func() { Format = FormatText })

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "text default", input: FormatText, want: FormatText},
		{name: "json", input: FormatJSON, want: FormatJSON},
		{name: "invalid", input: "yaml", wantErr: true},
		{name: "empty invalid", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetFormat(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("SetFormat() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("SetFormat() error = %v", err)
			}
			if Format != tt.want {
				t.Fatalf("Format = %q, want %q", Format, tt.want)
			}
			if IsJSON() != (tt.want == FormatJSON) {
				t.Fatalf("IsJSON() = %v, want %v", IsJSON(), tt.want == FormatJSON)
			}
		})
	}
}
