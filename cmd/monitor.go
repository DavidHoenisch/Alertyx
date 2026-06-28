/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/DavidHoenisch/Alertyx/common"
	"github.com/DavidHoenisch/Alertyx/utils"
	"github.com/spf13/cobra"
)

// monitorCmd represents the monitor command
var monitorCmd = &cobra.Command{
	Use:     "monitor",
	Aliases: []string{"m", "mon", "eyes"},
	Short:   "actively monitor for malicious action",
	Long: `Load eBPF modules and watch system activity in real time.
Detections are analyzed against registered MITRE ATT&CK techniques.`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.AlertyxMonitor()
	},
}

func init() {
	monitorCmd.Flags().BoolVarP(&common.Mitigate, "mitigate", "m", false, "attempt to mitigate detected techniques")
	monitorCmd.Flags().BoolVarP(&common.Duplicates, "duplicates", "d", false, "show duplicate detections")
	monitorCmd.Flags().StringSliceVarP(&common.IgnoreList, "ignore", "i", []string{}, "don't show certain event types in verbose mode (ex. -i open)")

}
