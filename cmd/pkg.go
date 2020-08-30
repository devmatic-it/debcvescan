package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// initializes arguments for pkg commmand
func init() {
	rootCmd.AddCommand(pkgCmd)
}

// pkg command
var pkgCmd = &cobra.Command{
	Use:   "pkg <package>",
	Short: "package vulnerabilities",
	Long:  `Give details of vulnerabilties of a package.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		report := analyze()

		// report vulnerabilities
		for _, vul := range report.Vulnerabilities {
			if vul.PackageName == args[0] {
				displayVulnerability(vul)
				fmt.Println()
			}
		}

	},
}
