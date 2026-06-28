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
	Short:   "check for and apply mitigations",
	Long: `Check registered detection techniques for mitigatable conditions.
Use --active to apply mitigations instead of reporting what would change.`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.AlertyxMitigate()
	},
}
