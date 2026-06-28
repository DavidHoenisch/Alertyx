package cmd

import (
	"testing"

	"github.com/DavidHoenisch/Alertyx/output"
)

func TestOutputFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered")
	}
	if flag.DefValue != output.FormatText {
		t.Fatalf("default = %q, want %q", flag.DefValue, output.FormatText)
	}
}

func TestOutputJSONFlag(t *testing.T) {
	t.Cleanup(func() {
		outputFormat = output.FormatText
		output.Format = output.FormatText
		rootCmd.SetArgs(nil)
	})

	rootCmd.SetArgs([]string{"--output", output.FormatJSON, "version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !output.IsJSON() {
		t.Fatalf("IsJSON() = false after --output json")
	}
}

func TestOutputFlagRejectsInvalidValue(t *testing.T) {
	t.Cleanup(func() {
		outputFormat = output.FormatText
		output.Format = output.FormatText
		rootCmd.SetArgs(nil)
	})

	rootCmd.SetArgs([]string{"--output", "xml", "version"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("Execute() expected error for invalid --output value")
	}
}
