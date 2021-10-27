package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
)

type ContainerScan struct {
	ImageName                  string                               `json:"imageName"`
	VulnerabilityScanTimestamp string                               `json:"vulnerabilityScanTimestamp"`
	Vulnerabilities            []ContainerScanVulnerability         `json:"vulnerabilities"`
	BestPracticeViolations     []ContainerScanBestPracticeViolation `json:"bestPracticeViolations"`
}

type ContainerScanVulnerability struct {
	VulnerabilityId string `json:"vulnerabilityId"`
	PackageName     string `json:"packageName"`
	Severity        string `json:"severity"`
	Description     string `json:"description"`
	Target          string `json:"target"`
}

type ContainerScanBestPracticeViolation struct {
	Code   string `json:"code"`
	Title  string `json:"title"`
	Level  string `json:"level"`
	Alerts string `json:"alerts"`
}

func main() {
	inputPath := flag.String("input", "./scanreport.json", "Path to the Azure Container Scan JSON Report")
	// outputPath := flag.String("output", "./scanreport.sarif", "Path to the SARIF output file")

	flag.Parse()

	input, err := ioutil.ReadFile(*inputPath)
	if err != nil {
		log.Fatal("Error when opening file: ", err)
	}

	var containerScan ContainerScan
	jsonUnmarshalErr := json.Unmarshal(input, &containerScan)
	if jsonUnmarshalErr != nil {
		log.Fatal("Error unmarshalling JSON: ", jsonUnmarshalErr)
	}
	fmt.Printf("containerScan: %+v", containerScan)
}
