# container-scan-to-sarif

[![Go Report Card](https://goreportcard.com/badge/github.com/rm3l/container-scan-to-sarif)](https://goreportcard.com/report/github.com/rm3l/container-scan-to-sarif)
[![Build](https://github.com/rm3l/container-scan-to-sarif/actions/workflows/build.yml/badge.svg)](https://github.com/rm3l/container-scan-to-sarif/actions/workflows/build.yml)
[![Release](https://github.com/rm3l/container-scan-to-sarif/actions/workflows/release.yml/badge.svg)](https://github.com/rm3l/container-scan-to-sarif/actions/workflows/release.yml)

`container-scan-to-sarif` converts [Azure Container Scan Action](https://github.com/Azure/container-scan#action-output) output to [Static Analysis Results Interchange Format (SARIF)](https://sarifweb.azurewebsites.net/), for an easier integration with tools like [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning).

## Rationale
The [Azure Container Scan Action](https://github.com/Azure/container-scan) combines both [Trivy](https://github.com/aquasecurity/trivy) 
and [Dockle](https://github.com/goodwithtech/dockle) tools to scan container images 
for common vulnerabilities (CVEs) and best practices violations. It also provides with the ability to ignore some checks 
if needed, via an [`allowedlist.yaml` file](https://github.com/Azure/container-scan#ignoring-vulnerabilities).

This is all great, but the resulting output is a non-standard JSON file, which, at this time,
can only be uploaded as a build artifact, making it hard to read across different CI runs or integrate with other tools.

On the other hand, [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning) integrates very well with external tools that are able to produce
[Static Analysis Results Interchange Format (SARIF)](https://sarifweb.azurewebsites.net/) reports, so users can navigate their reports in the nice 
"Code Scanning Alerts" interface.

This is where `container-scan-to-sarif` comes into play, by bridging the gap between Container Scan and other tools like GitHub Code Scanning.

It also started as a learning exercise for myself to use [Go](https://golang.org/) in practice.

## Installation

You can download the [latest release](https://github.com/rm3l/container-scan-to-sarif/releases/latest) of `container-scan-to-sarif`.

Or, from the sources:

```shell
go install github.com/rm3l/container-scan-to-sarif@latest
```

## Usage

### In GitHub Workflows

You may want to use the following Action in your Workflows: [rm3l/container-scan-to-sarif-action](https://github.com/rm3l/container-scan-to-sarif-action), like so:

```yaml
  - name: Scan Container Image
    id: scan
    continue-on-error: true
    uses: Azure/container-scan@v0.1
    with:
      image-name: my-container-image

  - name: Convert Container Scan Report to SARIF
    id: scan-to-sarif
    uses: rm3l/container-scan-to-sarif-action@v1
    if: ${{ always() }}
    with:
      input-file: ${{ steps.scan.outputs.scan-report-path }}

  - name: Upload SARIF reports to GitHub Security tab
    uses: github/codeql-action/upload-sarif@v1
    if: ${{ always() }}
    with:
      sarif_file: ${{ steps.scan-to-sarif.outputs.sarif-report-path }}
```

After your Workflow run passes, you should then be able to navigate the container scan report under your "Security > Code scanning alerts" tab.

### Standalone executable

#### Container image

Container images for `container-scan-to-sarif` are pushed to [GitHub Packages](https://github.com/rm3l/container-scan-to-sarif/pkgs/container/container-scan-to-sarif).
You can therefore run it with Docker, by mounting your Container Scan output inside the container, like so:

The working directory inside the container is set to `/data`. So you can just mount your Container Scan report under a `/data/scanreport.json` and run `container-scan-to-sarif`.
```shell
docker container run --rm \
  -v /path/to/my/container-scan-report.json:/data/scanreport.json \
  -t ghcr.io/rm3l/container-scan-to-sarif 
```

Alternatively, you can specify a different path (in the container), like so:
```shell
docker container run --rm \
  -v /path/to/my/container-scan-report.json:/tmp/my-scanreport.json \
  -t ghcr.io/rm3l/container-scan-to-sarif \
  -input /tmp/my-scanreport.json
```

#### CLI

```shell
container-scan-to-sarif --help

Usage of container-scan-to-sarif:
  -input string
        Path to the Container Scan JSON Report (default "./scanreport.json")
  -output string
        Path to the SARIF output file. If not specified, the resulting SARIF report will be pretty-printed to the standard output.
```

## Building from source

Once you have cloned this repo, you can build `container-scan-to-sarif` with the command below:

```shell
# Build
go build

# The executable can the be found here: ./container-scan-to-sarif
./container-scan-to-sarif --help
```

## Contribution Guidelines

Contributions and issue reporting are more than welcome. So to help out, do feel free to fork this repo and open up a pull request.
I'll review and merge your changes as quickly as possible.

You can use [GitHub issues](https://github.com/rm3l/container-scan-to-sarif/issues) to report bugs.
However, please make sure your description is clear enough and has sufficient instructions to be able to reproduce the issue.

## Developed by

* Armel Soro
    * [keybase.io/rm3l](https://keybase.io/rm3l)
    * [rm3l.org](https://rm3l.org) - &lt;armel+container-scan-to-sarif@rm3l.org&gt; - [@rm3l](https://twitter.com/rm3l)
    * [paypal.me/rm3l](https://paypal.me/rm3l)
    * [coinbase.com/rm3l](https://www.coinbase.com/rm3l)

## License

    The MIT License (MIT)

    Copyright (c) 2021 Armel Soro

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
