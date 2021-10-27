package containerscan

import (
	"encoding/json"
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

func ParseContainerScanReport(scanReportPath string) (ContainerScan, error) {
	var containerScan ContainerScan
	input, inputErr := ioutil.ReadFile(scanReportPath)
	if inputErr != nil {
		log.Println("Error when opening file: ", inputErr)
		return containerScan, inputErr
	}

	jsonUnmarshalErr := json.Unmarshal(input, &containerScan)
	if jsonUnmarshalErr != nil {
		log.Println("Error unmarshalling JSON: ", jsonUnmarshalErr)
	}
	return containerScan, jsonUnmarshalErr
}
