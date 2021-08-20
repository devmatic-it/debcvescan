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
	"testing"
)

func TestWhitelist_New(t *testing.T) {
	NewWhitelist()
}

func TestWhitelist_AddCVERemove(t *testing.T) {
	whitelist := NewWhitelist()
	whitelist.AddCVE("CVE-1245", "no risk")
	whitelist.RemoveCVE("CVE-1245")
}

func TestWhitelist_RemoveCVENotExists(t *testing.T) {
	whitelist := NewWhitelist()
	whitelist.AddCVE("CVE-1245", "no risk")
	whitelist.RemoveCVE("CVE-15")
}

func TestWhitlist_HasCVE(t *testing.T) {
	whitelist := NewWhitelist()
	whitelist.AddCVE("CVE-1245", "no risk")
	if !whitelist.HasCVE("CVE-1245") {
		t.Fail()
	}
}

func TestWhitelist_HasCVENotExists(t *testing.T) {
	whitelist := NewWhitelist()
	whitelist.AddCVE("CVE-1245", "no risk")
	if whitelist.HasCVE("CVE-0000") {
		t.Fail()
	}
}

func TestWhitelist_AddPackageRemove(t *testing.T) {
	whitelist := NewWhitelist()
	whitelist.AddPackage("bash", "no risk")
	whitelist.RemovePackage("bash")
}

func TestWhitelist_RemovePackageNotExists(t *testing.T) {
	whitelist := NewWhitelist()
	whitelist.AddPackage("bash", "no risk")
	whitelist.RemoveCVE("csh")
}

func TestWhitlist_HasPackage(t *testing.T) {
	whitelist := NewWhitelist()
	whitelist.AddCVE("bash", "no risk")
	if !whitelist.HasCVE("bash") {
		t.Fail()
	}
}

func TestWhitelist_HasPackageNotExists(t *testing.T) {
	whitelist := NewWhitelist()
	whitelist.AddCVE("bash", "no risk")
	if whitelist.HasCVE("csh") {
		t.Fail()
	}
}
