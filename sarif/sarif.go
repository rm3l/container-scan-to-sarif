package sarif

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/rm3l/container-scan-to-sarif/containerscan"
)

// regex to extract file path in case string includes (distro:version)
var re = regexp.MustCompile(`(?P<path>.+?)(?:\s*\((?:.*?)\).*?)?$`)

type SarifReport struct {
	Version string           `json:"version"`
	Schema  string           `json:"$schema"`
	Runs    []SarifReportRun `json:"runs"`
}
type SarifReportRun struct {
	Tool    SarifReportRunTool     `json:"tool"`
	Results []SarifReportRunResult `json:"results"`
}
type SarifReportRunTool struct {
	Driver     SarifReportRunToolDriver      `json:"driver"`
	Extensions []SarifReportRunToolExtension `json:"extensions"`
}
type SarifReportRunToolDriver struct {
	Name           string                         `json:"name"`
	InformationUri string                         `json:"informationUri"`
	FullName       string                         `json:"fullName"`
	Version        string                         `json:"version"`
	Rules          []SarifReportRunToolDriverRule `json:"rules"`
}
type SarifReportRunToolExtension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type SarifReportRunToolDriverRule struct {
	Id                   string                                           `json:"id"`
	Name                 *string                                          `json:"name,omitempty"`
	DefaultConfiguration SarifReportRunToolDriverRuleDefaultConfiguration `json:"defaultConfiguration"`
	ShortDescription     SarifReportRunToolDriverRuleDescription          `json:"shortDescription"`
	FullDescription      SarifReportRunToolDriverRuleDescription          `json:"fullDescription"`
	HelpUri              *string                                          `json:"helpUri,omitempty"`
	Help                 *SarifReportRunToolDriverRuleDescription         `json:"help,omitempty"`
}
type SarifReportRunToolDriverRuleDefaultConfiguration struct {
	Level string `json:"level"`
}
type SarifReportRunToolDriverRuleDescription struct {
	Text string `json:"text,omitempty"`
}
type SarifReportRunResult struct {
	RuleId    string                         `json:"ruleId"`
	Level     string                         `json:"level"`
	Message   SarifReportRunResultMessage    `json:"message"`
	Locations []SarifReportRunResultLocation `json:"locations,omitempty"`
}
type SarifReportRunResultMessage struct {
	Text string `json:"text"`
}
type SarifReportRunResultLocation struct {
	PhysicalLocation SarifReportRunResultLocationPhysicalLocation `json:"physicalLocation"`
}
type SarifReportRunResultLocationPhysicalLocation struct {
	ArtifactLocation SarifReportRunResultLocationPhysicalLocationArtifactLocation `json:"artifactLocation"`
	Region           *SarifReportRunResultLocationPhysicalLocationRegion          `json:"region,omitempty"`
}
type SarifReportRunResultLocationPhysicalLocationArtifactLocation struct {
	Uri   string `json:"uri"`
	Index *int   `json:"index,omitempty"`
}
type SarifReportRunResultLocationPhysicalLocationRegion struct {
	StartLine   *int `json:"startLine,omitempty"`
	StartColumn *int `json:"startColumn,omitempty"`
}

func FromContainerScan(containerScanReport containerscan.ContainerScan) (SarifReport, error) {
	sarifReport := SarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
	}
	sarifReportRunDriver := SarifReportRunToolDriver{
		Name:           "azure-container-scan",
		InformationUri: "https://github.com/Azure/container-scan",
		FullName:       "Azure Container Scan",
		Version:        "0.1",
	}
	sarifReportRun := SarifReportRun{}
	sarifReportRun.Tool.Extensions = append(sarifReportRun.Tool.Extensions,
		SarifReportRunToolExtension{
			Name:    "Trivy",
			Version: "latest",
		},
		SarifReportRunToolExtension{
			Name:    "Dockle",
			Version: "latest",
		})
	var rulesMap = map[string]SarifReportRunToolDriverRule{}
	//Trivy Vulnerabilities
	for _, vulnerability := range containerScanReport.Vulnerabilities {
		var level string
		switch vulnerability.Severity {
		case "CRITICAL", "HIGH":
			level = "error"
		case "MEDIUM":
			level = "warning"
		case "LOW", "UNKNOWN":
			level = "note"
		default:
			level = "none"
		}
		if _, ok := rulesMap[vulnerability.VulnerabilityId]; !ok {
			helpUri := fmt.Sprintf("https://avd.aquasec.com/nvd/%s", strings.ToLower(vulnerability.VulnerabilityId))
			rulesMap[vulnerability.VulnerabilityId] = SarifReportRunToolDriverRule{
				Id: vulnerability.VulnerabilityId,
				DefaultConfiguration: SarifReportRunToolDriverRuleDefaultConfiguration{
					Level: "warning",
				},
				ShortDescription: SarifReportRunToolDriverRuleDescription{
					Text: vulnerability.Description,
				},
				FullDescription: SarifReportRunToolDriverRuleDescription{
					Text: vulnerability.Description,
				},
				HelpUri: &helpUri,
			}
		}
		sarifRunResult := SarifReportRunResult{
			RuleId: vulnerability.VulnerabilityId,
			Level:  level,
			Message: SarifReportRunResultMessage{
				Text: vulnerability.Description,
			},
		}
		sarifRunResult.Locations = append(sarifRunResult.Locations,
			SarifReportRunResultLocation{
				PhysicalLocation: SarifReportRunResultLocationPhysicalLocation{
					ArtifactLocation: SarifReportRunResultLocationPhysicalLocationArtifactLocation{
						Uri: toPathUri(vulnerability.Target),
					},
				},
			})
		sarifReportRun.Results = append(sarifReportRun.Results, sarifRunResult)
	}

	//Dockle best practices violations
	for _, bestPracticeViolation := range containerScanReport.BestPracticeViolations {
		var level string
		switch bestPracticeViolation.Level {
		case "INFO":
			level = "note"
		case "WARN":
			level = "warning"
		case "FATAL":
			level = "error"
		default:
			level = "none"
		}
		if _, ok := rulesMap[bestPracticeViolation.Code]; !ok {
			helpUri := fmt.Sprintf("https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#%s", bestPracticeViolation.Code)
			rulesMap[bestPracticeViolation.Code] = SarifReportRunToolDriverRule{
				Id: bestPracticeViolation.Code,
				DefaultConfiguration: SarifReportRunToolDriverRuleDefaultConfiguration{
					Level: "warning",
				},
				ShortDescription: SarifReportRunToolDriverRuleDescription{
					Text: bestPracticeViolation.Title,
				},
				FullDescription: SarifReportRunToolDriverRuleDescription{
					Text: bestPracticeViolation.Title,
				},
				HelpUri: &helpUri,
			}
		}
		sarifRunResult := SarifReportRunResult{
			RuleId: bestPracticeViolation.Code,
			Level:  level,
			Message: SarifReportRunResultMessage{
				Text: bestPracticeViolation.Alerts,
			},
		}
		sarifReportRun.Results = append(sarifReportRun.Results, sarifRunResult)
	}
	sarifReportRun.Tool.Driver = sarifReportRunDriver
	rules := make([]SarifReportRunToolDriverRule, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}
	sarifReportRun.Tool.Driver.Rules = rules
	sarifReport.Runs = append(sarifReport.Runs, sarifReportRun)
	return sarifReport, nil
}

//Inpired from https://github.com/aquasecurity/trivy/blob/main/pkg/report/template.go
func toPathUri(input string) string {
	var result = input
	var matches = re.FindStringSubmatch(result)
	if matches != nil {
		result = matches[re.SubexpIndex("path")]
	}
	result = strings.ReplaceAll(result, "\\", "/")
	return result
}

func (report SarifReport) WriteTo(outputPath string) error {
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(outputPath, jsonData, 0644)
}
