package containerscan

import (
	"encoding/json"
	"log"
	"os"
)

type Report struct {
	ImageName                  string                  `json:"imageName"`
	VulnerabilityScanTimestamp string                  `json:"vulnerabilityScanTimestamp"`
	Vulnerabilities            []Vulnerability         `json:"vulnerabilities"`
	BestPracticeViolations     []BestPracticeViolation `json:"bestPracticeViolations"`
}

type Vulnerability struct {
	VulnerabilityId string `json:"vulnerabilityId"`
	PackageName     string `json:"packageName"`
	Severity        string `json:"severity"`
	Description     string `json:"description"`
	Target          string `json:"target"`
}

type BestPracticeViolation struct {
	Code   string `json:"code"`
	Title  string `json:"title"`
	Level  string `json:"level"`
	Alerts string `json:"alerts"`
}

func ParseReport(scanReportPath string) (Report, error) {
	var report Report
	input, err := os.ReadFile(scanReportPath)
	if err != nil {
		log.Println("error when reading file", err)
		return report, err
	}

	err = json.Unmarshal(input, &report)
	if err != nil {
		log.Println("error unmarshalling JSON", err)
	}
	return report, err
}
