/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/DavidHoenisch/Alertyx/utils"
	"github.com/spf13/cobra"
)

// mitigateCmd represents the mitigate command
var mitigateCmd = &cobra.Command{
	Use:     "mitigate",
	Aliases: []string{"mit", "cybpat"},
	Short:   "mitigate all known vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		utils.AlertyxMitigate()
	},
}

func init() {
	rootCmd.AddCommand(mitigateCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// mitigateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// mitigateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
