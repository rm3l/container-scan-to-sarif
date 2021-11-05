package main

import (
	"flag"
	"log"

	"github.com/rm3l/container-scan-to-sarif/containerscan"
	"github.com/rm3l/container-scan-to-sarif/sarif"
)

func main() {
	inputPath := flag.String("input", "./scanreport.json", "Path to the Container Scan JSON Report")
	outputPath := flag.String("output", "", "Path to the SARIF output file. If not specified, the resulting SARIF report will be pretty-printed to the standard output.")

	flag.Parse()

	containerScan, err := containerscan.ParseContainerScanReport(*inputPath)
	if err != nil {
		log.Fatal("Error when parsing file: ", err)
	}

	sarifReport, err := sarif.FromContainerScan(containerScan)
	if err != nil {
		log.Fatal("Could not construct SARIF report from Container Scan input: ", err)
	}

	sarifWriteErr := sarifReport.WriteTo(*outputPath)
	if sarifWriteErr != nil {
		log.Fatal("Could not write SARIF report: ", err)
	}
}
