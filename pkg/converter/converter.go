package converter

import (
	"fmt"
	"github.com/rm3l/container-scan-to-sarif/pkg/containerscan"
	"github.com/rm3l/container-scan-to-sarif/pkg/sarif"
	"strings"
)

const pathUriReplacement = "_"

func NewSarifReportFromContainerScanReport(containerScanReport containerscan.Report) (sarif.Report, error) {
	sarifReport := sarif.Report{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
	}
	sarifReportRunDriver := sarif.RunToolDriver{
		Name:           "container-scan",
		InformationUri: "https://github.com/Azure/container-scan",
		FullName:       "Container Scan",
		Version:        "0.1",
	}
	sarifReportRun := sarif.Run{}
	sarifReportRun.Tool.Extensions = append(sarifReportRun.Tool.Extensions,
		sarif.RunToolExtension{
			Name:    "Trivy",
			Version: "latest",
		},
		sarif.RunToolExtension{
			Name:    "Dockle",
			Version: "latest",
		})
	containerImageNameToPathUri := toPathUri(containerScanReport.ImageName)
	var rulesMap = map[string]sarif.RunToolDriverRule{}
	var partialFingerPrintsMap = map[string]string{}
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
			rulesMap[vulnerability.VulnerabilityId] = sarif.RunToolDriverRule{
				Id: vulnerability.VulnerabilityId,
				DefaultConfiguration: sarif.RunToolDriverRuleDefaultConfiguration{
					Level: "warning",
				},
				ShortDescription: sarif.RunToolDriverRuleDescription{
					Text: vulnerability.Description,
				},
				FullDescription: sarif.RunToolDriverRuleDescription{
					Text: vulnerability.Description,
				},
				Help: &sarif.RunToolDriverRuleDescription{
					Text: helpUri,
				},
			}
		}
		sarifRunResult := sarif.RunResult{
			RuleId: vulnerability.VulnerabilityId,
			Level:  level,
			Message: sarif.RunResultMessage{
				Text: vulnerability.Description,
			},
		}
		//startLine, endLine, startColumn, endColumn
		physicalLocationRegion := [4]uint{1, 1, 1, 1}
		sarifRunResult.Locations = append(sarifRunResult.Locations,
			sarif.RunResultLocation{
				PhysicalLocation: sarif.RunResultLocationPhysicalLocation{
					ArtifactLocation: sarif.RunResultLocationPhysicalLocationArtifactLocation{
						Uri: toPathUri(vulnerability.Target),
					},
					Region: &sarif.RunResultLocationPhysicalLocationRegion{
						StartLine:   &physicalLocationRegion[0],
						EndLine:     &physicalLocationRegion[1],
						StartColumn: &physicalLocationRegion[2],
						EndColumn:   &physicalLocationRegion[3],
					},
				},
			})
		sarifRunResult.PartialFingerprints = make(map[string]string)
		if _, exists := partialFingerPrintsMap[vulnerability.VulnerabilityId]; !exists {
			partialFingerPrintsMap[vulnerability.VulnerabilityId] = vulnerability.VulnerabilityId
			sarifRunResult.PartialFingerprints[vulnerability.VulnerabilityId] = vulnerability.VulnerabilityId
		}
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
			rulesMap[bestPracticeViolation.Code] = sarif.RunToolDriverRule{
				Id: bestPracticeViolation.Code,
				DefaultConfiguration: sarif.RunToolDriverRuleDefaultConfiguration{
					Level: "warning",
				},
				ShortDescription: sarif.RunToolDriverRuleDescription{
					Text: bestPracticeViolation.Title,
				},
				FullDescription: sarif.RunToolDriverRuleDescription{
					Text: bestPracticeViolation.Title,
				},
				Help: &sarif.RunToolDriverRuleDescription{
					Text: helpUri,
				},
			}
		}
		sarifRunResult := sarif.RunResult{
			RuleId: bestPracticeViolation.Code,
			Level:  level,
			Message: sarif.RunResultMessage{
				Text: bestPracticeViolation.Alerts,
			},
		}
		//startLine, endLine, startColumn, endColumn
		physicalLocationRegion := [4]uint{1, 1, 1, 1}
		sarifRunResult.Locations = append(sarifRunResult.Locations,
			sarif.RunResultLocation{
				PhysicalLocation: sarif.RunResultLocationPhysicalLocation{
					ArtifactLocation: sarif.RunResultLocationPhysicalLocationArtifactLocation{
						Uri: containerImageNameToPathUri,
					},
					Region: &sarif.RunResultLocationPhysicalLocationRegion{
						StartLine:   &physicalLocationRegion[0],
						EndLine:     &physicalLocationRegion[1],
						StartColumn: &physicalLocationRegion[2],
						EndColumn:   &physicalLocationRegion[3],
					},
				},
			})
		sarifRunResult.PartialFingerprints = make(map[string]string)
		if _, exists := partialFingerPrintsMap[bestPracticeViolation.Code]; !exists {
			partialFingerPrintsMap[bestPracticeViolation.Code] = bestPracticeViolation.Code
			sarifRunResult.PartialFingerprints[bestPracticeViolation.Code] = bestPracticeViolation.Code
		}
		sarifReportRun.Results = append(sarifReportRun.Results, sarifRunResult)
	}
	sarifReportRun.Tool.Driver = sarifReportRunDriver
	rules := make([]sarif.RunToolDriverRule, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}
	sarifReportRun.Tool.Driver.Rules = rules
	sarifReport.Runs = append(sarifReport.Runs, sarifReportRun)
	return sarifReport, nil
}

func toPathUri(input string) string {
	var inputSanitized = strings.ReplaceAll(input, ":", pathUriReplacement)
	inputSanitized = strings.ReplaceAll(inputSanitized, " ", pathUriReplacement)
	inputSanitized = strings.ReplaceAll(inputSanitized, "(", pathUriReplacement)
	inputSanitized = strings.ReplaceAll(inputSanitized, ")", pathUriReplacement)
	return inputSanitized
}
