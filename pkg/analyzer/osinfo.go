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
	"bufio"
	"log"
	"os"
	"strings"
)

type osSource int

const (
	sourceEtcOSRelease osSource = iota
	sourceUsrLibOsRelease
	sourceDataFallback
)

// GetOSInfo returns information about the Debian distro
func GetOSInfo() (string, string, string) {
	id, version, codename := getOSInfoFromFile(sourceEtcOSRelease)
	if id == "" {
		id, version, codename = getOSInfoFromFile(sourceUsrLibOsRelease)
	}
	if id == "" {
		id, version, codename = getOSInfoFromFile(sourceDataFallback)
	}
	return id, version, codename
}

func getOSInfoFromFile(source osSource) (string, string, string) {
	var path string
	switch source {
	case sourceEtcOSRelease:
		path = "/etc/os-release"
	case sourceUsrLibOsRelease:
		path = "/usr/lib/os-release"
	case sourceDataFallback:
		path = "../../data/os-release"
	default:
		return "", "", ""
	}

	id := "debian"
	version := "0.0"
	codename := "none"

	file, err := os.Open(path) // nosec G304
	if err != nil {
		return "", "", ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if strings.HasPrefix(text, "ID=") {
			id = strings.TrimPrefix(text, "ID=")
		} else if strings.HasPrefix(text, "VERSION_ID=") {
			version = strings.TrimPrefix(text, "VERSION_ID=\"")
			if len(version) > 0 && version[len(version)-1] == '"' {
				version = version[:len(version)-1]
			}
		} else if strings.HasPrefix(text, "VERSION_CODENAME=") {
			codename = strings.TrimPrefix(text, "VERSION_CODENAME=")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return id, version, codename
}
