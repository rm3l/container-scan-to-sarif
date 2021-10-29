package main

import (
	"flag"
	"log"

	"github.com/rm3l/container-scan-to-sarif/containerscan"
	"github.com/rm3l/container-scan-to-sarif/sarif"
)

func main() {
	inputPath := flag.String("input", "./scanreport.json", "Path to the Azure Container Scan JSON Report")
	outputPath := flag.String("output", "", "Path to the SARIF output file. Default output is STDOUT")

	flag.Parse()

	containerScan, err := containerscan.ParseContainerScanReport(*inputPath)
	if err != nil {
		log.Fatal("Error when parsing file: ", err)
	}
	// fmt.Printf("containerScan: %+v", containerScan)

	sarifReport, err := sarif.FromContainerScan(containerScan)
	if err != nil {
		log.Fatal("Could not construct SARIF report from Container Scan input: ", err)
	}
	// fmt.Printf("sarifReport: %+v", sarifReport)

	sarifWriteErr := sarifReport.WriteTo(*outputPath)
	if sarifWriteErr != nil {
		log.Fatal("Could not write SARIF report: ", err)
	}
}
