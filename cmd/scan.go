package cmd

import (
	"github.com/devmatic-it/debcvescan/pkg/reporter"
	"github.com/spf13/cobra"
)

// number of columns to be displayed per line
var displayColumns int

// display format, can be text or json
var displayFormat string

// syslogd host:port, default: localhost:514
var syslogHost string

// initializes arguments for scan command
func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().IntVarP(&displayColumns, "line-length", "t", 128, "number of columns displayed on screen")
	scanCmd.Flags().StringVarP(&displayFormat, "format", "f", "text", "display format")
	scanCmd.Flags().StringVarP(&syslogHost, "syslog-host", "s", "localhost:514", "syslogd host:port to stream TCP syslog events")
}

// scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "performs CVE scan",
	Long:  `Fetches the latest vulnerability list from the Debian Security Team and checks your installed packages.`,
	Run: func(cmd *cobra.Command, args []string) {
		report := analyze()
		switch displayFormat {
		case "text":
			reporter.GenerateTextReport(report, displayColumns)
			break
		case "json":
			reporter.GenerateJSONReport(report)
			break
		case "syslog":
			reporter.GenerateSyslogReport(report, syslogHost)
		}
	},
}
