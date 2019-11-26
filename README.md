# Debian CVE Tracker
[![Go Report Card](https://goreportcard.com/badge/github.com/devmatic-it/debcvescan)](https://goreportcard.com/report/github.com/devmatic-it/debcvescan)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/devmatic-it/debcvescan/blob/master/LICENSE)

The following project checks the installed packages of your Debian Linux distribution against known vulnerabilities of the Debian Security Bug Tracker https://security-tracker.debian.org/tracker/.

## Motivation
This project as been highly motivated by the CoreOS Clair Project (https://github.com/coreos/clair/) which provides a great security scanning solution for your docker images.
We aim to provide a replacement by the well known Debian Vulnerability scanning tool debsescan (https://wiki.debian.org/DebianSecurity/debsecan) this it has a following disadvantages:
- dependency on python runtime
- dependency to exim mail server

## Target
We want to provide the same features as the debsescan without dependencies to python or the exim mail server.
