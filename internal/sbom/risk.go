package sbom

import (
	"fmt"
	"strings"

	"imgscan/internal/config"
)

const (
	weightDirect    = 2.0
	weightTransitive = 1.0
	severityCritical = 10.0
	severityHigh     = 7.0
	severityMedium   = 4.0
	severityLow      = 1.0
	fixBonus         = -3.0
)

type RiskScorer struct {
	vulnerabilities []config.Vulnerability
	packages        []SBOMPackage
}

func NewRiskScorer(vulnerabilities []config.Vulnerability, packages []SBOMPackage) *RiskScorer {
	return &RiskScorer{
		vulnerabilities: vulnerabilities,
		packages:        packages,
	}
}

func (rs *RiskScorer) ScoreAll() map[string]float64 {
	scores := make(map[string]float64)

	pkgVulns := make(map[string][]config.Vulnerability)
	for _, v := range rs.vulnerabilities {
		key := strings.ToLower(v.PackageName)
		pkgVulns[key] = append(pkgVulns[key], v)
	}

	for _, pkg := range rs.packages {
		vulns := pkgVulns[strings.ToLower(pkg.Name)]
		score := rs.calculatePackageRisk(pkg, vulns)
		scores[pkg.ID] = score
	}

	return scores
}

func (rs *RiskScorer) calculatePackageRisk(pkg SBOMPackage, vulns []config.Vulnerability) float64 {
	if len(vulns) == 0 {
		return 0
	}

	var totalWeightedScore float64
	var totalWeight float64

	depWeight := weightDirect
	if !pkg.Provenance.IsDirect {
		depWeight = weightTransitive
	}

	for _, v := range vulns {
		severityScore := severityFromConfig(v.Severity)

		fixAdjustment := 0.0
		if v.FixedVersion != "" {
			fixAdjustment = fixBonus
		}

		weightedScore := (severityScore + fixAdjustment) * depWeight
		if weightedScore < 0 {
			weightedScore = 0
		}

		totalWeightedScore += weightedScore
		totalWeight += depWeight
	}

	if totalWeight == 0 {
		return 0
	}

	avgScore := totalWeightedScore / totalWeight
	normalizedScore := (avgScore / severityCritical) * 100

	if normalizedScore > 100 {
		normalizedScore = 100
	}

	return normalizedScore
}

func (rs *RiskScorer) CalculateTotalRisk(scores map[string]float64) float64 {
	var totalScore float64
	var totalWeight float64

	for _, pkg := range rs.packages {
		score, ok := scores[pkg.ID]
		if !ok {
			continue
		}

		weight := weightDirect
		if !pkg.Provenance.IsDirect {
			weight = weightTransitive
		}

		totalScore += score * weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		return 0
	}

	avgScore := totalScore / totalWeight
	if avgScore > 100 {
		avgScore = 100
	}

	return avgScore
}

func severityFromConfig(sev config.Severity) float64 {
	switch sev {
	case config.SeverityCritical:
		return severityCritical
	case config.SeverityHigh:
		return severityHigh
	case config.SeverityMedium:
		return severityMedium
	case config.SeverityLow:
		return severityLow
	default:
		return 0
	}
}

func MapVulnerabilitiesToPackages(vulns []config.Vulnerability, packages []SBOMPackage) []SBOMPackage {
	pkgMap := make(map[string]*SBOMPackage)
	for i := range packages {
		pkgMap[strings.ToLower(packages[i].Name)] = &packages[i]
	}

	for _, v := range vulns {
		pkg, ok := pkgMap[strings.ToLower(v.PackageName)]
		if !ok {
			continue
		}

		vulnURL := ""
		if v.CVE != "" {
			vulnURL = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CVE)
		}

		sbomVuln := SBOMVulnerability{
			PackageID:    pkg.ID,
			CVE:          v.CVE,
			ID:           v.ID,
			Severity:     v.Severity,
			URL:          vulnURL,
			FixedVersion: v.FixedVersion,
			Description:  v.Description,
			CVSS:         v.CVSS,
		}

		pkg.Vulnerabilities = append(pkg.Vulnerabilities, sbomVuln)

		found := false
		for _, ref := range pkg.ExternalRefs {
			if ref.Type == "cve" && ref.Locator == v.CVE {
				found = true
				break
			}
		}
		if !found && v.CVE != "" {
			pkg.ExternalRefs = append(pkg.ExternalRefs, ExternalRef{
				Category: "SECURITY",
				Type:     "cve",
				Locator:  vulnURL,
			})
		}
	}

	return packages
}

func FormatRiskReport(scores map[string]float64, totalScore float64) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Total Image Risk Score: %.1f/100\n\n", totalScore))

	var highRisk, medRisk, lowRisk []string
	for pkgID, score := range scores {
		if score > 0 {
			entry := fmt.Sprintf("%s: %.1f", pkgID, score)
			if score >= 70 {
				highRisk = append(highRisk, entry)
			} else if score >= 40 {
				medRisk = append(medRisk, entry)
			} else {
				lowRisk = append(lowRisk, entry)
			}
		}
	}

	if len(highRisk) > 0 {
		sb.WriteString("High Risk Packages:\n")
		for _, r := range highRisk {
			sb.WriteString(fmt.Sprintf("  ⚠ %s\n", r))
		}
	}

	if len(medRisk) > 0 {
		sb.WriteString("Medium Risk Packages:\n")
		for _, r := range medRisk {
			sb.WriteString(fmt.Sprintf("  △ %s\n", r))
		}
	}

	if len(lowRisk) > 0 {
		sb.WriteString("Low Risk Packages:\n")
		for _, r := range lowRisk {
			sb.WriteString(fmt.Sprintf("  ○ %s\n", r))
		}
	}

	return sb.String()
}
