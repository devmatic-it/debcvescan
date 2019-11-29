# Debian CVE Tracker

[![Go Report Card](https://goreportcard.com/badge/github.com/devmatic-it/debcvescan)](https://goreportcard.com/report/github.com/devmatic-it/debcvescan)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/devmatic-it/debcvescan/blob/master/LICENSE)

The following project checks the installed packages of your Debian Linux distribution against known vulnerabilities of the Debian Security Bug Tracker <https://security-tracker.debian.org/tracker>

## Motivation

The target of this project is to provider the CVE security scanning solution that is lightweight and self-contained. The current standard solution debsescan requires the following packages to be installed in order to run:

- dependency on python runtime
- dependency to exim mail server

We want to provide the same features as the debsescan without dependencies to python or the exim mail server.

## Installation

1. Download latest release for your platform: <https://github.com/devmatic-it/debcvescan/releases/latest>
2. extract archive: `tar xvfz debcvescan_X.Y.Z_amd64.tgz`
3. scan system for vulnerabilities: `debcvescan scan`

## Getting Started

1. Execute scanning: `debcvescan scan`
![debcvescan scan](ttps://github.com/devmatic-it/debcvescan/blob/master/docs/debcvescan_scan.png)

2. Scan a specific package for vulnerabilities: `debcvescan pkg vim`
![debcvescan scan](ttps://github.com/devmatic-it/debcvescan/blob/master/docs/debcvescan_pkg.png)

3. Get details for a specific vulnerabitities: `debcvescan cve CVE-12345`
![debcvescan scan](ttps://github.com/devmatic-it/debcvescan/blob/master/docs/debcvescan_cve.png)

## Contribute

TODO

## Credits

This work has ben inspired by the following open source projects:

- CoreOS Clair Project (<https://github.com/coreos/clair/)> 
- Debsescan Security Scanner (<https://gitlab.com/fweimer/debsecan)>
- GoRleaser Builder Image (<https://github.com/goreleaser/goreleaser)>
