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
	input, err := os.Open(scanReportPath)
	if err != nil {
		return report, err
	}
	defer func(input *os.File) {
		err := input.Close()
		if err != nil {
			log.Println("error while trying to close input file", err)
		}
	}(input)
	err = json.NewDecoder(input).Decode(&report)
	return report, err
}
