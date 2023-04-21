# Debian CVE Scanner

[![Go Report Card](https://goreportcard.com/badge/github.com/devmatic-it/debcvescan)](https://goreportcard.com/report/github.com/devmatic-it/debcvescan)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/devmatic-it/debcvescan/blob/master/LICENSE)
[![codecov](https://codecov.io/gh/devmatic-it/debcvescan/branch/master/graph/badge.svg)](https://codecov.io/gh/devmatic-it/debcvescan)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=devmatic-it_debcvescan&metric=alert_status)](https://sonarcloud.io/dashboard?id=devmatic-it_debcvescan)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=devmatic-it_debcvescan&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=devmatic-it_debcvescan)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=devmatic-it_debcvescan&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=devmatic-it_debcvescan)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=devmatic-it_debcvescan&metric=security_rating)](https://sonarcloud.io/dashboard?id=devmatic-it_debcvescan)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=devmatic-it_debcvescan&metric=bugs)](https://sonarcloud.io/dashboard?id=devmatic-it_debcvescan)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=devmatic-it_debcvescan&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=devmatic-it_debcvescan)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=devmatic-it_debcvescan&metric=code_smells)](https://sonarcloud.io/dashboard?id=devmatic-it_debcvescan)

The following project checks the installed packages of your Debian Linux distribution against known vulnerabilities of the Debian Security Bug Tracker <https://security-tracker.debian.org/tracker>

## Motivation

The target of this project is to provider the CVE security scanning solution that is lightweight and self-contained. The current standard solution debsescan requires the following packages to be installed in order to run:

- dependency on python runtime
- dependency to exim mail server

We want to provide the same features as the debsescan without dependencies to python or the exim mail server.

## Installation

### Binary

1. Download latest release for your platform: <https://github.com/devmatic-it/debcvescan/releases/latest>
2. extract archive: `tar xvfz debcvescan_X.Y.Z_linux_amd64.tgz`
3. scan system for vulnerabilities: `debcvescan scan`

### Debian package

1. Download latest release for your platform: <https://github.com/devmatic-it/debcvescan/releases/latest>
2. extract archive: `dpkg -i debcvescan_X.Y.Z_linux_amd64.deb`
3. scan system for vulnerabilities: `debcvescan scan`

### Debian Repository

1. Download and import public GPG key:

```bash
wget -qO - https://devmatic-it.github.io/debcvescan/debian/PUBLIC.KEY | sudo apt-key add -
```

2. Select sources directory for APT:

```bash
cd /etc/apt/sources.list.d`
```

3. Create new source file:

```bash
sudo echo "deb https://devmatic-it.github.io/debcvescan/debian buster main" > devmatic-it.list
```

4. Uodate APT repository:

```bash
sudo apt-get update
```

5. Install the package:

```bash
sudo apt-get install debcvescan
```

## Getting Started

1. Execute scanning: `debcvescan scan`
![debcvescan scan](https://github.com/devmatic-it/debcvescan/blob/master/docs/img/debcvescan_scan.png)

2. Scan a specific package for vulnerabilities: `debcvescan pkg cron`
![debcvescan scan](https://github.com/devmatic-it/debcvescan/blob/master/docs/img/debcvescan_pkg.png)

3. Get details for a specific vulnerabitities: `debcvescan cve CVE-2019-9704`
![debcvescan scan](https://github.com/devmatic-it/debcvescan/blob/master/docs/img/debcvescan_cve.png)

4. export scan report to JSON: `debcvescan scan --format=json`
![debcvescan scan](https://github.com/devmatic-it/debcvescan/blob/master/docs/img/debcvescan_scan_json.png)

5. scan/pkg an alternative filepath (global flag)
![debcvescan scan](https://github.com/devmatic-it/debcvescan/blob/master/docs/img/debcvescan_file.PNG)

## Contribute

### New Issues

1. Use the search tool before opening a new issue: <https://github.com/devmatic-it/debcvescan/issues>
2. Please provide source code and commit fix if you found a bug.
3. Review existing issues and provide feedback or react to them.

### Pull requests

1. Open your pull request against master:  <https://github.com/devmatic-it/debcvescan/pulls>
2. Your pull request should have no more than two commits, if not you should squash them.
3. It should pass all tests in the available continuous integrations systems such as TravisCI.
4. You should add/modify tests to cover your proposed code changes.
5. If your pull request contains a new feature, please document it on the <https://github.com/devmatic-it/debcvescan/blob/master/README.md>

## Credits

This work has ben inspired by the following open source projects:

- CoreOS Clair Project (<https://github.com/coreos/clair/>)
- Debsescan Security Scanner (<https://gitlab.com/fweimer/debsecan>)
- GoRleaser Builder Image (<https://github.com/goreleaser/goreleaser>)
- Building a basic CI/CD pipeline for a Golang application using GitHub Actions
(<https://dev.to/brpaz/building-a-basic-ci-cd-pipeline-for-a-golang-application-using-github-actions-icj>)
