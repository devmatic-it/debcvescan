package cmd

import (
	"os"

	"github.com/devmatic-it/debcvescan/pkg/analyzer"
	"github.com/devmatic-it/debcvescan/pkg/dpkg"
	"github.com/spf13/cobra"

	"fmt"
)

// config variables
var (
	rootCmd = &cobra.Command{
		Use:   "debcvescan",
		Short: "Debian CVE Scanner",
		Long: `Debian CVE Scanner


CVE Security Scanner for Debian Linux distributions using official Debian Security Bug Tracker <https://security-tracker.debian.org/tracker>.
I has no dependencies to other libraries and is self-contained compared to the official PERL implementation.
		`,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
)

// Execute runs the root cobra command for the gelp
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// analyzes installed packages
func analyze() analyzer.VulnerabilityReport {

	// load installed packages
	installedPackages := dpkg.LoadInstalledPackages("/var/lib/dpkg/status")
	// scan for vulnerabilties
	vulnerabilities := analyzer.ScanPackages(installedPackages)
	return vulnerabilities
}

// displays detailed description of the given vulnerability
func displayVulnerability(vul analyzer.Vulnerability) {
	fmt.Println(vul.CVE)
	fmt.Printf("Package: %s\n", vul.PackageName)
	fmt.Printf("Installed Version: %s\n", vul.InstalledVersion)
	fmt.Printf("Fixed Verion: %s\n", vul.FixedVersion)
	fmt.Println("Description:")
	fmt.Println(vul.Description)
}
