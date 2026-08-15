package config

import "testing"

func TestGetExitCode_FailOnHigh(t *testing.T) {
	ignore, err := LoadIgnoreList("")
	if err != nil {
		t.Fatal(err)
	}
	result := &ScanResult{
		Vulnerabilities: []Vulnerability{{
			CVE:      "CVE-2024-2",
			Severity: SeverityHigh,
		}},
	}
	got := GetExitCode(result, SeverityHigh, ignore)
	if got != 1 {
		t.Fatalf("GetExitCode(failOn=High, one High)=%d, want 1", got)
	}
}
