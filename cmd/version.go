package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// ProductVersion contains the product version injected by the build system
var ProductVersion string = "0.0.0"

// initializes arguments for version command
func init() {
	rootCmd.AddCommand(versionCmd)
}

// version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "product version",
	Long:  `provides version information.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("debcvescan: %s\n", ProductVersion)
		fmt.Printf("go version: %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	},
}
