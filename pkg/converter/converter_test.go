package converter_test

import (
	"github.com/google/go-cmp/cmp"
	"github.com/rm3l/container-scan-to-sarif/pkg/containerscan"
	"github.com/rm3l/container-scan-to-sarif/pkg/converter"
	"github.com/rm3l/container-scan-to-sarif/pkg/sarif"
	"testing"
)

func TestNewSarifReportFromContainerScanReport(t *testing.T) {
	containerScanReport := containerscan.Report{
		ImageName:                  "myacr.azurecr.io/testapp:770aed6bd33d7240b4bdb55f16348ce37b86bb09",
		VulnerabilityScanTimestamp: "2021-03-05T09:38:48.036Z",
		Vulnerabilities: []containerscan.Vulnerability{
			{
				VulnerabilityId: "CVE-2018-12886",
				PackageName:     "gcc-8-base",
				Severity:        "HIGH",
				Description:     "stack_protect_prologue in cfgexpand.c and stack_protect_epilogue in function.c in GNU Compiler Collection (GCC) 4.1 through 8 (under certain circumstances) generate instruction sequences when targeting ARM targets that spill the address of the stack protector guard, which allows an attacker to bypass the protection of -fstack-protector, -fstack-protector-all, -fstack-protector-strong, and -fstack-protector-explicit against stack overflow by controlling what the stack canary is compared against.",
				Target:          "myacr.azurecr.io/ascdemo:770aed6bd33d7240b4bdb55f16348ce37b86bb09 (debian 10.4)",
			},
			{
				VulnerabilityId: "CVE-2019-20367",
				PackageName:     "libbsd0",
				Severity:        "CRITICAL",
				Description:     "nlist.c in libbsd before 0.10.0 has an out-of-bounds read during a comparison for a symbol name from the string table (strtab).",
				Target:          "myacr.azurecr.io/ascdemo:770aed6bd33d7240b4bdb55f16348ce37b86bb09 (debian 10.4)",
			},
		},
		BestPracticeViolations: []containerscan.BestPracticeViolation{
			{
				Code:   "CIS-DI-0001",
				Title:  "Create a user for the container",
				Level:  "WARN",
				Alerts: "Last user should not be root",
			},
			{
				Code:   "CIS-DI-0005",
				Title:  "Enable Content trust for Docker",
				Level:  "INFO",
				Alerts: "export DOCKER_CONTENT_TRUST=1 before docker pull/build",
			},
		},
	}

	sarifReport, err := converter.NewSarifReportFromContainerScanReport(containerScanReport)
	if err != nil {
		t.Error("unexpected error", err)
	}

	var locationRegion uint = 1

	expectedSarifReport := sarif.Report{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
		Runs: []sarif.Run{
			{
				Tool: sarif.RunTool{
					Driver: sarif.RunToolDriver{
						Name:           "container-scan",
						InformationUri: "https://github.com/Azure/container-scan",
						FullName:       "Container Scan",
						Version:        "0.1",
						Rules: []sarif.RunToolDriverRule{
							{
								Id:   "CIS-DI-0001",
								Name: nil,
								DefaultConfiguration: sarif.RunToolDriverRuleDefaultConfiguration{
									Level: "warning",
								},
								ShortDescription: sarif.RunToolDriverRuleDescription{
									Text: "Create a user for the container",
								},
								FullDescription: sarif.RunToolDriverRuleDescription{
									Text: "Create a user for the container"},
								HelpUri: nil,
								Help: &sarif.RunToolDriverRuleDescription{
									Text: "https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#CIS-DI-0001",
								},
							},
							{
								Id:   "CIS-DI-0005",
								Name: nil,
								DefaultConfiguration: sarif.RunToolDriverRuleDefaultConfiguration{
									Level: "warning",
								},
								ShortDescription: sarif.RunToolDriverRuleDescription{
									Text: "Enable Content trust for Docker",
								},
								FullDescription: sarif.RunToolDriverRuleDescription{
									Text: "Enable Content trust for Docker"},
								HelpUri: nil,
								Help: &sarif.RunToolDriverRuleDescription{
									Text: "https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#CIS-DI-0005",
								},
							},
							{
								Id:   "CVE-2018-12886",
								Name: nil,
								DefaultConfiguration: sarif.RunToolDriverRuleDefaultConfiguration{
									Level: "warning",
								},
								ShortDescription: sarif.RunToolDriverRuleDescription{
									Text: "stack_protect_prologue in cfgexpand.c and stack_protect_epilogue in function.c in GNU Compiler Collection (GCC) 4.1 through 8 (under certain circumstances) generate instruction sequences when targeting ARM targets that spill the address of the stack protector guard, which allows an attacker to bypass the protection of -fstack-protector, -fstack-protector-all, -fstack-protector-strong, and -fstack-protector-explicit against stack overflow by controlling what the stack canary is compared against.",
								},
								FullDescription: sarif.RunToolDriverRuleDescription{
									Text: "stack_protect_prologue in cfgexpand.c and stack_protect_epilogue in function.c in GNU Compiler Collection (GCC) 4.1 through 8 (under certain circumstances) generate instruction sequences when targeting ARM targets that spill the address of the stack protector guard, which allows an attacker to bypass the protection of -fstack-protector, -fstack-protector-all, -fstack-protector-strong, and -fstack-protector-explicit against stack overflow by controlling what the stack canary is compared against."},
								HelpUri: nil,
								Help: &sarif.RunToolDriverRuleDescription{
									Text: "https://avd.aquasec.com/nvd/cve-2018-12886",
								},
							},
							{
								Id:   "CVE-2019-20367",
								Name: nil,
								DefaultConfiguration: sarif.RunToolDriverRuleDefaultConfiguration{
									Level: "warning",
								},
								ShortDescription: sarif.RunToolDriverRuleDescription{
									Text: "nlist.c in libbsd before 0.10.0 has an out-of-bounds read during a comparison for a symbol name from the string table (strtab).",
								},
								FullDescription: sarif.RunToolDriverRuleDescription{
									Text: "nlist.c in libbsd before 0.10.0 has an out-of-bounds read during a comparison for a symbol name from the string table (strtab)."},
								HelpUri: nil,
								Help: &sarif.RunToolDriverRuleDescription{
									Text: "https://avd.aquasec.com/nvd/cve-2019-20367",
								},
							},
						},
					},
					Extensions: []sarif.RunToolExtension{
						{
							Name:    "Dockle",
							Version: "latest",
						},
						{
							Name:    "Trivy",
							Version: "latest",
						},
					},
				},
				Results: []sarif.RunResult{
					{
						RuleId: "CIS-DI-0001",
						Level:  "warning",
						Message: sarif.RunResultMessage{
							Text: "Last user should not be root",
						},
						Locations: []sarif.RunResultLocation{
							{
								PhysicalLocation: sarif.RunResultLocationPhysicalLocation{
									ArtifactLocation: sarif.RunResultLocationPhysicalLocationArtifactLocation{
										Uri:   "myacr.azurecr.io/testapp_770aed6bd33d7240b4bdb55f16348ce37b86bb09",
										Index: nil,
									},
									Region: &sarif.RunResultLocationPhysicalLocationRegion{
										StartLine:   &locationRegion,
										StartColumn: &locationRegion,
										EndLine:     &locationRegion,
										EndColumn:   &locationRegion,
									},
								},
							},
						},
						PartialFingerprints: map[string]string{
							"CIS-DI-0001": "CIS-DI-0001",
						},
					},
					{
						RuleId: "CIS-DI-0005",
						Level:  "note",
						Message: sarif.RunResultMessage{
							Text: "export DOCKER_CONTENT_TRUST=1 before docker pull/build",
						},
						Locations: []sarif.RunResultLocation{
							{
								PhysicalLocation: sarif.RunResultLocationPhysicalLocation{
									ArtifactLocation: sarif.RunResultLocationPhysicalLocationArtifactLocation{
										Uri:   "myacr.azurecr.io/testapp_770aed6bd33d7240b4bdb55f16348ce37b86bb09",
										Index: nil,
									},
									Region: &sarif.RunResultLocationPhysicalLocationRegion{
										StartLine:   &locationRegion,
										StartColumn: &locationRegion,
										EndLine:     &locationRegion,
										EndColumn:   &locationRegion,
									},
								},
							},
						},
						PartialFingerprints: map[string]string{
							"CIS-DI-0005": "CIS-DI-0005",
						},
					},
					{
						RuleId: "CVE-2018-12886",
						Level:  "error",
						Message: sarif.RunResultMessage{
							Text: "stack_protect_prologue in cfgexpand.c and stack_protect_epilogue in function.c in GNU Compiler Collection (GCC) 4.1 through 8 (under certain circumstances) generate instruction sequences when targeting ARM targets that spill the address of the stack protector guard, which allows an attacker to bypass the protection of -fstack-protector, -fstack-protector-all, -fstack-protector-strong, and -fstack-protector-explicit against stack overflow by controlling what the stack canary is compared against.",
						},
						Locations: []sarif.RunResultLocation{
							{
								PhysicalLocation: sarif.RunResultLocationPhysicalLocation{
									ArtifactLocation: sarif.RunResultLocationPhysicalLocationArtifactLocation{
										Uri:   "myacr.azurecr.io/ascdemo_770aed6bd33d7240b4bdb55f16348ce37b86bb09__debian_10.4_",
										Index: nil,
									},
									Region: &sarif.RunResultLocationPhysicalLocationRegion{
										StartLine:   &locationRegion,
										StartColumn: &locationRegion,
										EndLine:     &locationRegion,
										EndColumn:   &locationRegion,
									},
								},
							},
						},
						PartialFingerprints: map[string]string{
							"CVE-2018-12886": "CVE-2018-12886",
						},
					},
					{
						RuleId: "CVE-2019-20367",
						Level:  "error",
						Message: sarif.RunResultMessage{
							Text: "nlist.c in libbsd before 0.10.0 has an out-of-bounds read during a comparison for a symbol name from the string table (strtab).",
						},
						Locations: []sarif.RunResultLocation{
							{
								PhysicalLocation: sarif.RunResultLocationPhysicalLocation{
									ArtifactLocation: sarif.RunResultLocationPhysicalLocationArtifactLocation{
										Uri:   "myacr.azurecr.io/ascdemo_770aed6bd33d7240b4bdb55f16348ce37b86bb09__debian_10.4_",
										Index: nil,
									},
									Region: &sarif.RunResultLocationPhysicalLocationRegion{
										StartLine:   &locationRegion,
										StartColumn: &locationRegion,
										EndLine:     &locationRegion,
										EndColumn:   &locationRegion,
									},
								},
							},
						},
						PartialFingerprints: map[string]string{
							"CVE-2019-20367": "CVE-2019-20367",
						},
					},
				},
			},
		},
	}
	if diff := cmp.Diff(expectedSarifReport, sarifReport); diff != "" {
		t.Error(diff)
	}
}
