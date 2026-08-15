package config

import (
	"bufio"
	"os"
	"strings"
)

type IgnoreList struct {
	CVEs      map[string]bool
	Packages  map[string]bool
}

func LoadIgnoreList(path string) (*IgnoreList, error) {
	if path == "" {
		return &IgnoreList{
			CVEs:     make(map[string]bool),
			Packages: make(map[string]bool),
		}, nil
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &IgnoreList{
			CVEs:     make(map[string]bool),
			Packages: make(map[string]bool),
		}, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ignore := &IgnoreList{
		CVEs:     make(map[string]bool),
		Packages: make(map[string]bool),
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "CVE-") || strings.HasPrefix(line, "GHSA-") {
			ignore.CVEs[line] = true
		} else {
			ignore.Packages[line] = true
		}
	}

	return ignore, scanner.Err()
}

func (i *IgnoreList) IsVulnerabilityIgnored(v Vulnerability) bool {
	if i.CVEs[v.CVE] || i.CVEs[v.ID] {
		return true
	}
	if i.Packages[v.PackageName] {
		return true
	}
	return false
}

func (i *IgnoreList) FilterVulnerabilities(vulns []Vulnerability) []Vulnerability {
	var filtered []Vulnerability
	for _, v := range vulns {
		if !i.IsVulnerabilityIgnored(v) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func GetExitCode(result *ScanResult, failOn Severity, ignore *IgnoreList) int {
	severityOrder := map[Severity]int{
		SeverityCritical: 4,
		SeverityHigh:     3,
		SeverityMedium:   2,
		SeverityLow:      1,
		SeverityNone:     0,
	}

	targetLevel := severityOrder[failOn]

	vulns := ignore.FilterVulnerabilities(result.Vulnerabilities)

	var critical, high int
	for _, v := range vulns {
		if severityOrder[v.Severity] > targetLevel {
			switch v.Severity {
			case SeverityCritical:
				critical++
			case SeverityHigh:
				high++
			}
		}
	}

	if critical > 0 {
		return 2
	}
	if high > 0 {
		return 1
	}
	return 0
}
