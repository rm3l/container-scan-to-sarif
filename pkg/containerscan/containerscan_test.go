package containerscan_test

import (
	"github.com/google/go-cmp/cmp"
	"github.com/rm3l/container-scan-to-sarif/pkg/containerscan"
	"testing"
)

func TestParseReport(t *testing.T) {
	_, err := containerscan.ParseReport("testdata/non_existing_container_scan_output.json")
	if err == nil {
		t.Error("expected an error, but got none")
	}

	expectedReport := containerscan.Report{
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
			{
				VulnerabilityId: "CVE-2020-1751",
				PackageName:     "libc-bin",
				Severity:        "HIGH",
				Description:     "An out-of-bounds write vulnerability was found in glibc before 2.31 when handling signal trampolines on PowerPC. Specifically, the backtrace function did not properly check the array bounds when storing the frame address, resulting in a denial of service or potential code execution. The highest threat from this vulnerability is to system availability.",
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
	report, err := containerscan.ParseReport("testdata/containerscan_sample_output.json")
	if err != nil {
		t.Error(err)
	}
	if diff := cmp.Diff(expectedReport, report); diff != "" {
		t.Error(diff)
	}
}
