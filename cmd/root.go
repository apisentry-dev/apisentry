package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "apisentry",
	Short: "APISentry — AI-powered API security scanner",
	Long:  `APISentry scans your API for OWASP Top 10 vulnerabilities using AI-powered attack generation.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
