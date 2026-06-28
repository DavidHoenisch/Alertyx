package cmd

import (
	"github.com/DavidHoenisch/Alertyx/utils"
	"github.com/spf13/cobra"
)

// huntCmd represents the hunt command
var huntCmd = &cobra.Command{
	Use:     "hunt",
	Aliases: []string{"h", "hun"},
	Short:   "hunt for evidence of known attack techniques",
	Long: `Run passive hunts across registered detection techniques to find
signs of compromise. Use --active to clean evidence and optionally mitigate
when findings are confirmed.`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.AlertyxHunt()
	},
}
