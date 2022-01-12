package main

import (
	"flag"
	"github.com/rm3l/container-scan-to-sarif/pkg/containerscan"
	"github.com/rm3l/container-scan-to-sarif/pkg/converter"
	"log"
)

func main() {
	inputPath := flag.String("input", "./scanreport.json", "path to the Container Scan JSON Report")
	outputPath := flag.String("output", "", "path to the SARIF output file. If not specified, the resulting SARIF report will be pretty-printed to the standard output")
	verbose := flag.Bool("verbose", false, "verbose output")

	flag.Parse()

	containerScanReport, err := containerscan.ParseReport(*inputPath)
	if err != nil {
		log.Fatal("error when parsing file: ", err)
	}

	sarifReport, err := converter.NewSarifReportFromContainerScanReport(containerScanReport)
	if err != nil {
		log.Fatal("could not construct SARIF report from Container Scan input: ", err)
	}

	err = sarifReport.WriteTo(*outputPath, *verbose)
	if err != nil {
		log.Fatal("could not write SARIF report: ", err)
	}
}
