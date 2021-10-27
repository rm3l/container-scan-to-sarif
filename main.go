package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/rm3l/container-scan-to-sarif/containerscan"
)

func main() {
	inputPath := flag.String("input", "./scanreport.json", "Path to the Azure Container Scan JSON Report")
	// outputPath := flag.String("output", "./scanreport.sarif", "Path to the SARIF output file")

	flag.Parse()

	containerScan, err := containerscan.ParseContainerScanReport(*inputPath)
	if err != nil {
		log.Fatal("Error when parsing file: ", err)
	}
	fmt.Printf("containerScan: %+v", containerScan)
}
