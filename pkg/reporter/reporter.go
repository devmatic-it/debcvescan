// Package reporter Debian CVE Tracker Analyzer
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
package reporter

import (
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"

	"github.com/devmatic-it/debcvescan/pkg/analyzer"
)

// GenerateTextReport generates a text report
func GenerateTextReport(report analyzer.VulnerabilityReport, displayColumns int) {
	fmt.Printf("Summary Total:%d Open:%d High: %d Medium: %d Low: %d Unknown: %d Ignored: %d \n", report.CountTotal, report.CountOpen, report.CountHigh, report.CountMedium, report.CountLow, report.CountUnknown, report.CountIgnore)
	for _, vul := range report.Vulnerabilities {

		maxLen := len(vul.Description)
		if displayColumns < maxLen {
			maxLen = displayColumns
		}

		fmt.Printf("%-12s %-6s %s: %s \n", vul.PackageName, vul.Severity, vul.CVE, vul.Description[:maxLen])
	}
}

// GenerateJSONReport generates a JSON report
func GenerateJSONReport(report analyzer.VulnerabilityReport) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))
}

// GenerateSyslogReport generates syslogd reports
func GenerateSyslogReport(report analyzer.VulnerabilityReport, host string) {
	sysLog, err := syslog.Dial("tcp", host, syslog.LOG_WARNING|syslog.LOG_DAEMON, "debcvescan")
	if err != nil {
		log.Fatal(err)
	}

	for _, vul := range report.Vulnerabilities {
		message := fmt.Sprintf("%-12s %-6s %s: %s \n", vul.PackageName, vul.Severity, vul.CVE, vul.Description)
		if vul.Severity == analyzer.LOW {
			err = sysLog.Info(message)
			if err != nil {
				log.Fatal(err)
			}

		} else if vul.Severity == analyzer.MEDIUM {
			err = sysLog.Warning(message)
			if err != nil {
				log.Fatal(err)
			}

		} else if vul.Severity == analyzer.HIGH {
			err = sysLog.Err(message)
			if err != nil {
				log.Fatal(err)
			}

		} else if vul.Severity == analyzer.IGNORE {
			err = sysLog.Notice(message)
			if err != nil {
				log.Fatal(err)
			}

		} else if vul.Severity == analyzer.UNKNOWN {
			err = sysLog.Warning(message)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}
