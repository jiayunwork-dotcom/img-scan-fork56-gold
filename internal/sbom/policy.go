package sbom

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type PolicyEngine struct {
	policy *Policy
}

func NewPolicyEngine(policyPath string) (*PolicyEngine, error) {
	if policyPath == "" {
		return &PolicyEngine{policy: nil}, nil
	}

	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	return &PolicyEngine{policy: &policy}, nil
}

func (pe *PolicyEngine) Evaluate(doc *SBOMDocument) PolicyResult {
	result := PolicyResult{}

	if pe.policy == nil {
		return result
	}

	pe.evaluateLicenses(doc, &result)
	pe.evaluateSignature(doc, &result)
	pe.evaluateRiskScore(doc, &result)
	pe.evaluateBannedPackages(doc, &result)

	return result
}

func (pe *PolicyEngine) evaluateLicenses(doc *SBOMDocument, result *PolicyResult) {
	if len(pe.policy.AllowedLicenses) == 0 && len(pe.policy.DeniedLicenses) == 0 {
		return
	}

	allowedSet := make(map[string]bool)
	for _, lic := range pe.policy.AllowedLicenses {
		allowedSet[strings.ToUpper(lic)] = true
	}
	deniedSet := make(map[string]bool)
	for _, lic := range pe.policy.DeniedLicenses {
		deniedSet[strings.ToUpper(lic)] = true
	}

	for _, pkg := range doc.Packages {
		licenses := splitLicenseExpression(pkg.LicenseConcluded)
		if len(licenses) == 0 {
			licenses = splitLicenseExpression(pkg.LicenseDeclared)
		}
		if len(licenses) == 0 {
			continue
		}

		for _, lic := range licenses {
			licUpper := strings.ToUpper(lic)

			if len(pe.policy.AllowedLicenses) > 0 && !allowedSet[licUpper] && licUpper != "NOASSERTION" {
				result.Failed = append(result.Failed, PolicyRuleResult{
					RuleID:   "POL-LIC-001",
					RuleName: "Allowed License",
					Passed:   false,
					Details:  fmt.Sprintf("Package %s has license %s which is not in the allowed list", pkg.Name, lic),
				})
			}

			if deniedSet[licUpper] {
				result.Failed = append(result.Failed, PolicyRuleResult{
					RuleID:   "POL-LIC-002",
					RuleName: "Denied License",
					Passed:   false,
					Details:  fmt.Sprintf("Package %s uses denied license %s", pkg.Name, lic),
				})
			}
		}
	}

	if len(pe.policy.AllowedLicenses) > 0 && len(result.Failed) == 0 {
		result.Passed = append(result.Passed, PolicyRuleResult{
			RuleID:   "POL-LIC-001",
			RuleName: "Allowed License",
			Passed:   true,
			Details:  "All package licenses are in the allowed list",
		})
	}
	if len(pe.policy.DeniedLicenses) > 0 {
		deniedViolations := false
		for _, f := range result.Failed {
			if f.RuleID == "POL-LIC-002" {
				deniedViolations = true
				break
			}
		}
		if !deniedViolations {
			result.Passed = append(result.Passed, PolicyRuleResult{
				RuleID:   "POL-LIC-002",
				RuleName: "Denied License",
				Passed:   true,
				Details:  "No package uses a denied license",
			})
		}
	}
}

func (pe *PolicyEngine) evaluateSignature(doc *SBOMDocument, result *PolicyResult) {
	if !pe.policy.RequireSignature {
		return
	}

	if doc.Signature.HasCosignSignature {
		result.Passed = append(result.Passed, PolicyRuleResult{
			RuleID:   "POL-SIG-001",
			RuleName: "Require Signature",
			Passed:   true,
			Details:  "Image has valid cosign signature",
		})
	} else {
		result.Failed = append(result.Failed, PolicyRuleResult{
			RuleID:   "POL-SIG-001",
			RuleName: "Require Signature",
			Passed:   false,
			Details:  "Image is not signed - supply chain integrity cannot be verified",
		})
	}
}

func (pe *PolicyEngine) evaluateRiskScore(doc *SBOMDocument, result *PolicyResult) {
	if pe.policy.MaxRiskScore <= 0 {
		return
	}

	if doc.TotalRiskScore <= pe.policy.MaxRiskScore {
		result.Passed = append(result.Passed, PolicyRuleResult{
			RuleID:   "POL-RISK-001",
			RuleName: "Max Risk Score",
			Passed:   true,
			Details:  fmt.Sprintf("Image risk score %.1f is within threshold %.1f", doc.TotalRiskScore, pe.policy.MaxRiskScore),
		})
	} else {
		result.Failed = append(result.Failed, PolicyRuleResult{
			RuleID:   "POL-RISK-001",
			RuleName: "Max Risk Score",
			Passed:   false,
			Details:  fmt.Sprintf("Image risk score %.1f exceeds threshold %.1f", doc.TotalRiskScore, pe.policy.MaxRiskScore),
		})
	}
}

func (pe *PolicyEngine) evaluateBannedPackages(doc *SBOMDocument, result *PolicyResult) {
	if len(pe.policy.BannedPackages) == 0 {
		return
	}

	var compiledPatterns []*regexp.Regexp
	for _, pattern := range pe.policy.BannedPackages {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		compiledPatterns = append(compiledPatterns, re)
	}

	var banned []string
	for _, pkg := range doc.Packages {
		for _, re := range compiledPatterns {
			if re.MatchString(pkg.Name) {
				banned = append(banned, fmt.Sprintf("%s (matched pattern: %s)", pkg.Name, re.String()))
			}
		}
	}

	if len(banned) > 0 {
		result.Failed = append(result.Failed, PolicyRuleResult{
			RuleID:   "POL-PKG-001",
			RuleName: "Banned Packages",
			Passed:   false,
			Details:  fmt.Sprintf("Found banned packages: %s", strings.Join(banned, ", ")),
		})
	} else {
		result.Passed = append(result.Passed, PolicyRuleResult{
			RuleID:   "POL-PKG-001",
			RuleName: "Banned Packages",
			Passed:   true,
			Details:  "No banned packages found",
		})
	}
}

func splitLicenseExpression(expr string) []string {
	if expr == "" || expr == "NOASSERTION" {
		return nil
	}

	expr = strings.ReplaceAll(expr, "(", "")
	expr = strings.ReplaceAll(expr, ")", "")

	var licenses []string

	if strings.Contains(expr, " OR ") {
		for _, part := range strings.Split(expr, " OR ") {
			licenses = append(licenses, strings.TrimSpace(part))
		}
		return licenses
	}

	if strings.Contains(expr, " AND ") {
		for _, part := range strings.Split(expr, " AND ") {
			licenses = append(licenses, strings.TrimSpace(part))
		}
		return licenses
	}

	if strings.Contains(expr, " WITH ") {
		licenses = append(licenses, expr)
		return licenses
	}

	licenses = append(licenses, expr)
	return licenses
}

func HasPolicyViolations(result PolicyResult) bool {
	return len(result.Failed) > 0
}

func FormatPolicyResult(result PolicyResult) string {
	var sb strings.Builder

	if len(result.Passed) > 0 {
		sb.WriteString("Policy Checks Passed:\n")
		for _, r := range result.Passed {
			sb.WriteString(fmt.Sprintf("  ✓ [%s] %s: %s\n", r.RuleID, r.RuleName, r.Details))
		}
	}

	if len(result.Failed) > 0 {
		sb.WriteString("Policy Violations:\n")
		for _, r := range result.Failed {
			sb.WriteString(fmt.Sprintf("  ✗ [%s] %s: %s\n", r.RuleID, r.RuleName, r.Details))
		}
	}

	if len(result.Passed) == 0 && len(result.Failed) == 0 {
		sb.WriteString("No policy rules evaluated (no policy file specified)\n")
	}

	return sb.String()
}
