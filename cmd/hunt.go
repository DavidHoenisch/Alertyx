package cmd

import (
	"github.com/DavidHoenisch/Alertyx/utils"
	"github.com/spf13/cobra"
)

// hunCmd represents the hun command
var huntCmd = &cobra.Command{
	Use:     "mitigate",
	Aliases: []string{"mit", "cybpat"},
	Short:   "mitigate all known vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		utils.AlertyxHunt()
	},
}

func init() {
	rootCmd.AddCommand(huntCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// hunCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// hunCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
