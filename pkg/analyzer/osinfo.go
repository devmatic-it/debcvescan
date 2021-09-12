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

// GetOSInfo returns information about the Debian distro
func GetOSInfo() (string, string, string) {
	id := "debian"
	version := "0.0"
	codename := "none"
	file, err := os.Open("/etc/os-release")
	if err == nil {
		file, _ = os.Open("/usr/lib/os-release")
	}
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if strings.HasPrefix(text, "ID=") {
			id = strings.TrimPrefix(text, "ID=")
		} else if strings.HasPrefix(text, "VERSION=") {
			version = strings.TrimPrefix(text, "VERSION=")
		} else if strings.HasPrefix(text, "CODENAME=") {
			codename = strings.TrimPrefix(text, "CODENAME=")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return id, version, codename
}
