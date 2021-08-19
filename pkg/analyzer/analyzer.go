// Package analyzer Debian CVE Tracker Analyzer
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
package analyzer

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/devmatic-it/debcvescan/pkg/dpkg"
)

// Severity describs the severity
type Severity int

const (
	// OPEN open issue still beein investigated
	OPEN Severity = iota

	// HIGH  critical issue to be fixef
	HIGH

	// MEDIUM  medium severity
	MEDIUM

	// LOW  low severity
	LOW
	// UNKNOWN unknown impact
	UNKNOWN

	// IGNORE end of life and outdated issues
	IGNORE
)

func (serverity Severity) String() string {
	return [...]string{"OPEN", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "IGNORE"}[serverity]
}

// Vulnerability contains a vulnerability
type Vulnerability struct {
	Severity         Severity `json:"severity"`
	CVE              string   `json:"cve"`
	Description      string   `json:"description"`
	PackageName      string   `json:"package"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version"`
}

// VulnerabilityReport vulnerability report
type VulnerabilityReport struct {
	CountTotal      int             `json:"count_total"`
	CountHigh       int             `json:"count_high"`
	CountMedium     int             `json:"count_medium"`
	CountLow        int             `json:"count_low"`
	CountUnknown    int             `json:"count_unknown"`
	CountIgnore     int             `json:"count_ignore"`
	CountOpen       int             `json:"count_open"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type jsonData map[string]map[string]jsonVulnerability

type jsonVulnerability struct {
	Description string                 `json:"description"`
	Releases    map[string]jsonRelease `json:"releases"`
}

type jsonRelease struct {
	FixedVersion string `json:"fixed_version"`
	Status       string `json:"status"`
	Urgency      string `json:"urgency"`
}

// converts urgency to serverity
func severityFromUrgency(urgency string) Severity {
	switch urgency {

	case "low", "low*", "low**":
		return LOW

	case "medium", "medium*", "medium**":
		return MEDIUM

	case "high", "high*", "high**":
		return HIGH

	case "not yet assigned":
		return OPEN

	case "end-of-life", "unimportant":
		return IGNORE

	default:
		return UNKNOWN
	}
}

// ScanPackages scans the given list of debian packages for vulnerabilties
func ScanPackages(installedPackages dpkg.PackageList) VulnerabilityReport {

	cvejson, err := os.Open("./debcvelist.json")
	if err != nil {

		client := &http.Client{}
		req, err := http.NewRequest("GET", "https://security-tracker.debian.org/tracker/data/json", nil)
		if err != nil {
			panic(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}

		return scanPackagesFromReader(resp.Body, installedPackages)

	}

	return scanPackagesFromReader(cvejson, installedPackages)
}

// scans for vulnerabilities in given packages
func scanPackagesFromReader(source io.Reader, installedPackages dpkg.PackageList) VulnerabilityReport {
	report := VulnerabilityReport{}

	var data jsonData
	err := json.NewDecoder(source).Decode(&data)
	if err != nil {
		panic(err)
	}

	whitelist := NewWhitelist()
	report.CountTotal = 0
	cveNames := make(map[string]string)
	for pkgName, pkgNode := range data {
		pkgInstalledVersion, pkgExists := installedPackages[pkgName]
		if pkgExists {
			for vulnName, vulnNode := range pkgNode {
				for _, releaseNode := range vulnNode.Releases {
					if !strings.HasPrefix(vulnName, "CVE-") || releaseNode.Status == "undetermined" {
						continue
					}

					_, exists := cveNames[vulnName]
					if !exists && dpkg.IsAffectedVersion(pkgInstalledVersion, releaseNode.FixedVersion) {
						cveNames[vulnName] = pkgName
						severity := severityFromUrgency(releaseNode.Urgency)
						if releaseNode.Status == "Open" {
							severity = OPEN
						}

						// statistics
						switch severity {
						case OPEN:
							report.CountOpen++
							break
						case HIGH:
							report.CountHigh++
							break
						case MEDIUM:
							report.CountMedium++
							break
						case LOW:
							report.CountLow++
							break
						case IGNORE:
							report.CountIgnore++
							break
						case UNKNOWN:
							report.CountUnknown++
							break
						}

						if !whitelist.IsWhitelisted(vulnName) {
							if severity == LOW || severity == MEDIUM || severity == HIGH || severity == OPEN {
								report.Vulnerabilities = append(report.Vulnerabilities, Vulnerability{severity, vulnName, vulnNode.Description, pkgName, pkgInstalledVersion, releaseNode.FixedVersion})
							}
						}

						report.CountTotal++
					}

				}
			}
		}

	}

	return report
}
