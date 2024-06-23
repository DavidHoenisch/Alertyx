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
	Run: func(cmd *cobra.Command, args []string) {
		utils.AlertyxMonitor()
	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// monitorCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// monitorCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	monitorCmd.Flags().BoolVarP(&common.Mitigate, "mitigate", "m", false, "attempt to mitigate detected techniques")
	monitorCmd.Flags().BoolVarP(&common.Duplicates, "duplicates", "d", false, "show duplicate detections")
	monitorCmd.Flags().StringSliceVarP(&common.IgnoreList, "ignore", "i", []string{}, "don't show certain event types in verbose mode (ex. -i open)")

}
