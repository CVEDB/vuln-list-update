# vuln-list-update

[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]
[![Update vuln-list repo](https://github.com/cvedb/vuln-list-update/actions/workflows/update.yml/badge.svg)](https://github.com/cvedb/vuln-list-update/actions/workflows/update.yml)

[report-card-img]: https://goreportcard.com/badge/github.com/cvedb/vuln-list-update
[report-card]: https://goreportcard.com/report/github.com/cvedb/vuln-list-update
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[license]: https://github.com/cvedb/vuln-list-update/blob/main/LICENSE

Automatically collect vulnerability information and save it in a parseable format.

Collected data is stored in the [vuln-list repository](https://github.com/cvedb/vuln-list/).

## Usage

Run `vuln-list-update -h` to display the available options:

```text
$ vuln-list-update -h
Usage of vuln-list-update:
  -target string
        update target (nvd, alpine, alpine-unfixed, redhat, redhat-oval, redhat-csaf-vex, debian, ubuntu, amazon, bottlerocket, oracle-oval, suse-cvrf, photon, arch-linux, glad, cwe, osvdev, mariner, kevc, wolfi, chainguard, azure, openeuler, echo, echo-osv, minimos, eoldates, rootio, seal, alma, rocky)
  -vuln-list-dir string
        vuln-list dir
  -target-branch string
        alternative repository branch (only glad)
  -target-uri string
        alternative repository URI (only glad)
```

## Project layout

- `main.go` parses CLI options and dispatches each `-target` to an updater.
- Source-specific packages live at the repository root, for example `alpine/`, `ubuntu/`, and `nvd/`. Related implementations are grouped by format or API under directories such as `debian/tracker/`, `redhat/`, `oracle/oval/`, and `suse/cvrf/`.
- `utils/` contains shared download, filesystem, and repository helpers. `osv/` contains shared OSV types; `osvdev/` is the OSV data updater.
- Tests and their fixtures are kept beside each package, typically in `*_test.go` and `testdata/` (including golden files).
- `scripts/` contains repository scripts, while `.github/` contains GitHub automation.

Run `go test -race ./...` to test all packages, or use `make test` and `make build`.

## Author
khulnaSoft (khulnasoft)
