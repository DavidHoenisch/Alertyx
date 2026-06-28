/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/DavidHoenisch/Alertyx/common"
	"github.com/DavidHoenisch/Alertyx/output"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "Alertyx",
	Short: "Linux endpoint detection and response",
	Long: `Alertyx is a Linux endpoint detection and response (EDR) tool.
It uses eBPF to monitor system activity and detect techniques mapped to MITRE ATT&CK.

Use monitor for real-time detection, hunt for evidence of past activity,
and mitigate to check or apply remediation for known issues.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func configureOutput(cmd *cobra.Command, args []string) error {
	if err := output.SetFormat(outputFormat); err != nil {
		return err
	}
	output.Init()
	return nil
}

var outputFormat string

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.Alertyx.yaml)")

	rootCmd.PersistentFlags().BoolVarP(&common.Active, "active", "a", false, "counter detected malicious activity (dangerous, may clobber)")
	rootCmd.PersistentFlags().BoolVarP(&output.Verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&output.Syslog, "syslog", "s", false, "output to syslog")
	rootCmd.PersistentFlags().StringVar(&outputFormat, "output", output.FormatText, "output format: text or json")
	rootCmd.PersistentPreRunE = configureOutput
	rootCmd.AddCommand(monitorCmd, huntCmd, mitigateCmd, versionCmd)
}
