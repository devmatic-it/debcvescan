// Package dpkg Debian Package Manager Interface
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
package dpkg

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// PackageList contains a list of installed packages
type PackageList map[string]string

// LoadInstalledPackages Loads installed packages from /var/lib/dppkg/status file
func LoadInstalledPackages(path string) PackageList {
	packages := make(PackageList)
	reader, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(reader)
	pkgName := ""
	pkgVersion := ""
	pkgInstalled := false
	for scanner.Scan() {
		row := scanner.Text()
		items := strings.Split(row, ":")
		key := items[0]

		if len(items) > 1 {
			value := strings.Trim(items[1], " ")
			if key == "Package" {
				pkgName = value
				pkgInstalled = false
			} else if key == "Version" && pkgInstalled {
				pkgVersion = value
				if len(items) > 2 {
					pkgVersion = items[1] + ":" + items[2]
				}

				packages[pkgName] = pkgVersion
			} else if key == "Status" {
				if strings.Contains(value, "installed") {
					pkgInstalled = true
				}
			}
		}
	}

	return packages
}

// IsAffectedVersion returns true, if the current version < fixed version
func IsAffectedVersion(current, fixed string) bool {
	re := regexp.MustCompile(`[a-z+ ]`)
	currentEpoch := strings.ReplaceAll(current, ":", ".")
	fixedEpoch := strings.ReplaceAll(fixed, ":", ".")
	currentTags := strings.Split(strings.ReplaceAll(currentEpoch, "-", "."), ".")
	fixedTags := strings.Split(strings.ReplaceAll(fixedEpoch, "-", "."), ".")
	count := len(fixedTags)
	if count > len(currentTags) {
		count = len(currentTags)
	}

	for i := 0; i < count; i++ {
		curTag := re.ReplaceAllString(currentTags[i], "")
		curVer, err1 := strconv.Atoi(curTag)

		fixedTag := re.ReplaceAllString(fixedTags[i], "")
		fixedVer, err2 := strconv.Atoi(fixedTag)

		if err1 == nil && err2 == nil {
			if curVer < fixedVer {
				return true
			} else if curVer > fixedVer {
				return false
			}
		}
	}
	return false
}
