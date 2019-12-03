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
package dpkg

import "testing"

func TestIsAffectedVersion_false(t *testing.T) {
	if IsAffectedVersion("2.2.4-1ubuntu1.2", "2.0.9-1") {
		t.Fail()
	}
}

func TestIsAffectedVersion_true(t *testing.T) {
	if !IsAffectedVersion("1.9.4-1ubuntu1.2", "2.0.9-1") {
		t.Fail()
	}
}

func TestIsAffectedVersion_false2(t *testing.T) {
	if IsAffectedVersion("2.1.5+deb1+cvs20081104-13.2", "2.1.5+deb1+cvs20081104-13.2") {
		t.Fail()
	}
}

func TestIsAffectedVersion_false3(t *testing.T) {
	if IsAffectedVersion("1.12.2-1ubuntu1.1", "1.4.12-1") {
		t.Fail()
	}
}

func TestIsAffectedVersion_false4(t *testing.T) {
	if IsAffectedVersion(" 1.29b-2ubuntu0.1", "1.15.1-3") {
		t.Fail()
	}
}

func TestIsAffectedVersion_false5(t *testing.T) {
	if IsAffectedVersion("2.9.4+dfsg1-6.1ubuntu1.2", "2.9.2+really2.9.1+dfsg1-0.1") {
		t.Fail()
	}
}

func TestLoadInstalledPackages1(t *testing.T) {
	packages := LoadInstalledPackages("../../data/dpkg/status")
	if packages == nil {
		t.Fail()
	}

	if len(packages) != 940 {
		t.Errorf("Expected 940 packages, but found %d", len(packages))
	}

	bashVersion, found := packages["bash"]
	if !found {
		t.Error("Cannot find package bash")
	}

	if bashVersion != "4.4.18-2ubuntu1.2" {
		t.Errorf("Expected bash package version 4.4.18-2ubuntu1.2, but found %s", bashVersion)
	}

}
