// Package main Debian CVE Tracker Analyzer
// Copyright 2019 debcvescan authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/devmatic-it/debcvescan/pkg/analyzer"
	"github.com/devmatic-it/debcvescan/pkg/dpkg"
	"github.com/devmatic-it/debcvescan/pkg/reporter"
)

// number of columns to be displayed per line
var displayColumns int

// display format, can be text or json
var displayFormat string

// syslogd host:port, default: localhost:514
var syslogHost string

// scan command
var scanCommand *flag.FlagSet

// init initializes tge command line arguments
func init() {
	scanCommand = flag.NewFlagSet("scan", flag.ExitOnError)
	scanCommand.IntVar(&displayColumns, "line-length", 128, "number of columns displayed on screen")
	scanCommand.StringVar(&displayFormat, "format", "text", "display format")
	scanCommand.StringVar(&syslogHost, "syslog-host", "localhost:514", "syslogd host:port to stream TCP syslog events")
}

// displays a help messag
func displayHelp() {
	fmt.Println("Debian CVE Scanner")
	fmt.Println()
	fmt.Println("fetches the latest vulnerabilties from the official Debian CVE tracker and displays the results with the installed packages.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  debcvescan scan|cve|pkg [<CVE>|<package>] [OPTIONS]")
	fmt.Println()
	flag.PrintDefaults()
	scanCommand.PrintDefaults()
	os.Exit(1)
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

// analyzes installed packages
func analyze() analyzer.VulnerabilityReport {
	// load installed packages
	installedPackages := dpkg.LoadInstalledPackages("/var/lib/dpkg/status")
	// scan for vulnerabilties
	vulnerabilities := analyzer.ScanPackages(installedPackages)
	return vulnerabilities
}

// scans existing packages and prints out a summary report
func executeScan() {
	scanCommand.Parse(os.Args[2:])

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
}

// displays detailed report for given CVE
func excecuteCVE() {
	if len(os.Args) < 3 {
		displayHelp()
	}
	cve := os.Args[2]
	cveCommand := flag.NewFlagSet("cve", flag.ContinueOnError)
	cveCommand.Parse(os.Args[3:])

	if len(os.Args) < 3 {
		displayHelp()
	}

	report := analyze()

	// report vulnerabilities
	for _, vul := range report.Vulnerabilities {
		if vul.CVE == cve {
			displayVulnerability(vul)
			break
		}
	}

}

// detailed description of vulnerabilties for a given package
func excecutePackage() {
	if len(os.Args) < 3 {
		displayHelp()
	}

	pkg := strings.Trim(os.Args[2], " ")
	pkgCommand := flag.NewFlagSet("pkg", flag.ContinueOnError)
	pkgCommand.Parse(os.Args[3:])

	report := analyze()

	// report vulnerabilities
	for _, vul := range report.Vulnerabilities {
		if vul.PackageName == pkg {
			displayVulnerability(vul)
			fmt.Println()
		}
	}
}

// main entry point
func main() {
	if len(os.Args) < 2 {
		displayHelp()
	}

	switch os.Args[1] {
	case "scan":
		executeScan()
	case "pkg":
		excecutePackage()
	case "cve":
		excecuteCVE()
	default:
		displayHelp()
	}
}
