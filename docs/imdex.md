---
title: DEBCVESCAN
permalink: index.html
---
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

1.Download and import public GPG key:

```bash
wget -qO - https://devmatic-it.github.io/debcvescan/debian/PUBLIC.KEY | sudo apt-key add -
```

2.Select sources directory for APT:

```bash
cd /etc/apt/sources.list.d`
```

3.Create new source file:

```bash
sudo echo "deb https://devmatic-it.github.io/debcvescan/debian buster main" > devmatic-it.list
```

4.Uodate APT repository:

```bash
sudo apt-get update
```

5.Install the package:

```bash
sudo apt-get install debcvescan
```

## Getting Started

1. Execute scanning: `debcvescan scan`
![debcvescan scan](https://github.com/devmatic-it/debcvescan/blob/master/docs/img/debcvescan_scan.png)

2. Scan a specific package for vulnerabilities: `debcvescan pkg vim`
![debcvescan scan](https://github.com/devmatic-it/debcvescan/blob/master/docs/img/debcvescan_pkg.png)

3. Get details for a specific vulnerabitities: `debcvescan cve CVE-12345`
![debcvescan scan](https://github.com/devmatic-it/debcvescan/blob/master/docs/img/debcvescan_cve.png)

4. export scan report to JSON: `debcvescan scan --format=json`
![debcvescan scan](https://github.com/devmatic-it/debcvescan/blob/master/docs/img/debcvescan_scan_json.png)

## Credits

This work has ben inspired by the following open source projects:

- CoreOS Clair Project (<https://github.com/coreos/clair/>)
- Debsescan Security Scanner (<https://gitlab.com/fweimer/debsecan>)
- GoRleaser Builder Image (<https://github.com/goreleaser/goreleaser>)
- Building a basic CI/CD pipeline for a Golang application using GitHub Actions
(<https://dev.to/brpaz/building-a-basic-ci-cd-pipeline-for-a-golang-application-using-github-actions-icj>)
