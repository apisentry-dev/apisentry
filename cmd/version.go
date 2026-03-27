package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var appVersion = "dev"

// SetVersion is called from main.go to inject the build-time version string.
func SetVersion(v string) {
	appVersion = v
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print APISentry version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("apisentry", appVersion)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
