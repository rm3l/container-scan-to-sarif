package main

import (
	"flag"
	"fmt"
	"github.com/rm3l/container-scan-to-sarif/pkg/containerscan"
	"github.com/rm3l/container-scan-to-sarif/pkg/converter"
	"log"
)

func main() {
	inputPath := flag.String("input", "./scanreport.json", "path to the Container Scan JSON Report")
	flag.Parse()

	containerScanReport, err := containerscan.ParseReport(*inputPath)
	if err != nil {
		log.Fatal(err)
	}

	sarifReport, err := converter.NewSarifReportFromContainerScanReport(containerScanReport)
	if err != nil {
		log.Fatal("could not construct SARIF report from Container Scan input: ", err)
	}

	sarifAsJsonString, err := sarifReport.ToJsonString()
	if err != nil {
		log.Fatal("could not write SARIF report: ", err)
	}
	fmt.Println(sarifAsJsonString)
}
