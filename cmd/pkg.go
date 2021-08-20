package cmd

import (
	"fmt"

	"github.com/devmatic-it/debcvescan/pkg/analyzer"
	"github.com/spf13/cobra"
)

// initializes arguments for pkg command
func init() {
	pkgCmd.Flags().BoolVar(&pkgRemoveWhitelist, "remove-whitelist", false, "removes a package from the './debcvescan.whitelist' file")
	pkgCmd.Flags().StringVar(&pkgAddWhitelist, "add-whitelist", "", "adds a package to the './debcvescan.whitelist' file including a justification")
	rootCmd.AddCommand(pkgCmd)
}

var pkgAddWhitelist = ""
var pkgRemoveWhitelist = false

// pkg command
var pkgCmd = &cobra.Command{
	Use:   "pkg <package>",
	Short: "package vulnerabilities",
	Long:  `Give details of vulnerabilties of a package.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		whitelist := analyzer.NewWhitelist()
		if pkgAddWhitelist != "" {
			whitelist.AddPackage(args[0], pkgAddWhitelist)
		} else if pkgRemoveWhitelist {
			whitelist.RemovePackage(args[0])
		} else {

			report := analyze()

			// report vulnerabilities
			for _, vul := range report.Vulnerabilities {
				if vul.PackageName == args[0] {
					displayVulnerability(vul)
					fmt.Println()
				}
			}
		}

	},
}
