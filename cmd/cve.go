package cmd

import (
	"fmt"

	"github.com/devmatic-it/debcvescan/pkg/analyzer"
	"github.com/spf13/cobra"
)

// initializes arguments for pkg command
func init() {
	cveCmd.Flags().BoolVar(&cveRemoveWhitelist, "remove-whitelist", false, "removes a CVE from the './debcvescan.whitelist' file")
	cveCmd.Flags().StringVar(&cveAddWhitelist, "add-whitelist", "", "adds a CVE to the './debcvescan.whitelist' file including a justification")
	cveCmd.Flags().BoolVar(&cveShowWhitelist, "show-whitelist", false, "shows all whitelisted CVEs including justification from the './debcvescan.whitelist' file")
	rootCmd.AddCommand(cveCmd)
}

// cve command
var cveRemoveWhitelist = false
var cveShowWhitelist = false
var cveAddWhitelist = ""
var cveCmd = &cobra.Command{
	Use:   "cve <cve>",
	Short: "CVE details",
	Long:  `shows details of given CVE <cve>.`,
	Run: func(cmd *cobra.Command, args []string) {
		whitelisted := analyzer.NewWhitelist()
		if cveAddWhitelist != "" {
			if len(args) == 0 {
				fmt.Println("error, <cve> required")
				return
			}

			whitelisted.Add(args[0], cveAddWhitelist)
		} else if cveRemoveWhitelist {
			if len(args) == 0 {
				fmt.Println("error, <cve> required")
				return
			}

			whitelisted.Remove(args[0])
		} else if cveShowWhitelist {
			for _, entry := range whitelisted.Whitelisted {
				fmt.Printf("%s: %s\n", entry.CVE, entry.Justification)
			}
		} else {
			if len(args) == 0 {
				fmt.Println("error, <cve> required")
				return
			}
			report := analyze()

			// report vulnerabilities
			for _, vul := range report.Vulnerabilities {
				if vul.CVE == args[0] {
					displayVulnerability(vul)
					break
				}
			}
		}
	},
}
