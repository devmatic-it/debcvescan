package cmd

import (
	"github.com/spf13/cobra"
)

// initializes arguments for pkg command
func init() {
	rootCmd.AddCommand(cveCmd)

}

// cve command
var cveCmd = &cobra.Command{
	Use:   "cve <cve>",
	Short: "CVE details",
	Long:  `shows details of given CVE <cve>.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		report := analyze()

		// report vulnerabilities
		for _, vul := range report.Vulnerabilities {
			if vul.CVE == args[0] {
				displayVulnerability(vul)
				break
			}
		}
	},
}
