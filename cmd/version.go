/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/DavidHoenisch/Alertyx/common"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print the Alertyx version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(common.Version)
	},
}
