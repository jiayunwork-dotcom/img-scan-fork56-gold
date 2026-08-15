package diff

import (
	"sort"

	"imgscan/internal/config"
	"imgscan/internal/utils"
	"imgscan/internal/version"
)

func Compare(oldResult, newResult *config.ScanResult) *config.DiffResult {
	diff := &config.DiffResult{
		OldImage: oldResult.ImageName,
		NewImage: newResult.ImageName,
		ScanTime: utils.NowISO(),
	}

	diff.VulnerabilityDiff = compareVulnerabilities(oldResult.Vulnerabilities, newResult.Vulnerabilities)
	diff.PackageDiff = comparePackages(oldResult.Packages, newResult.Packages)
	diff.LayerDiff = compareLayers(oldResult.Layers, newResult.Layers)
	diff.ComplianceDiff = compareCompliance(oldResult.Compliance, newResult.Compliance)

	return diff
}

func compareVulnerabilities(oldVulns, newVulns []config.Vulnerability) config.VulnerabilityDiff {
	oldMap := make(map[string]config.Vulnerability)
	for _, v := range oldVulns {
		key := v.CVE + "|" + v.PackageName + "|" + v.PackageVersion
		oldMap[key] = v
	}

	newMap := make(map[string]config.Vulnerability)
	for _, v := range newVulns {
		key := v.CVE + "|" + v.PackageName + "|" + v.PackageVersion
		newMap[key] = v
	}

	var result config.VulnerabilityDiff

	for key, v := range newMap {
		if _, exists := oldMap[key]; !exists {
			result.Added = append(result.Added, v)
		} else {
			result.Unchanged = append(result.Unchanged, v)
		}
	}

	for key, v := range oldMap {
		if _, exists := newMap[key]; !exists {
			result.Removed = append(result.Removed, v)
		}
	}

	sort.Slice(result.Added, func(i, j int) bool {
		return severityOrder(result.Added[i].Severity) < severityOrder(result.Added[j].Severity)
	})
	sort.Slice(result.Removed, func(i, j int) bool {
		return severityOrder(result.Removed[i].Severity) < severityOrder(result.Removed[j].Severity)
	})
	sort.Slice(result.Unchanged, func(i, j int) bool {
		return severityOrder(result.Unchanged[i].Severity) < severityOrder(result.Unchanged[j].Severity)
	})

	return result
}

func severityOrder(s config.Severity) int {
	switch s {
	case config.SeverityCritical:
		return 0
	case config.SeverityHigh:
		return 1
	case config.SeverityMedium:
		return 2
	case config.SeverityLow:
		return 3
	default:
		return 4
	}
}

func comparePackages(oldPkgs, newPkgs []config.Package) config.PackageDiff {
	oldMap := make(map[string]config.Package)
	for _, p := range oldPkgs {
		key := string(p.Type) + "|" + p.Name
		oldMap[key] = p
	}

	newMap := make(map[string]config.Package)
	for _, p := range newPkgs {
		key := string(p.Type) + "|" + p.Name
		newMap[key] = p
	}

	var result config.PackageDiff

	for key, p := range newMap {
		if oldP, exists := oldMap[key]; exists {
			if oldP.Version != p.Version {
				comparer := version.GetComparer(string(p.Type))
				change := config.PackageChange{
					Package:    p,
					OldVersion: oldP.Version,
					NewVersion: p.Version,
				}
				if comparer(p.Version, oldP.Version) > 0 {
					change.ChangeType = "upgraded"
					result.Upgraded = append(result.Upgraded, change)
				} else {
					change.ChangeType = "downgraded"
					result.Downgraded = append(result.Downgraded, change)
				}
			} else {
				result.Unchanged = append(result.Unchanged, p)
			}
		} else {
			result.Added = append(result.Added, p)
		}
	}

	for key, p := range oldMap {
		if _, exists := newMap[key]; !exists {
			result.Removed = append(result.Removed, p)
		}
	}

	sort.Slice(result.Added, func(i, j int) bool {
		return result.Added[i].Name < result.Added[j].Name
	})
	sort.Slice(result.Removed, func(i, j int) bool {
		return result.Removed[i].Name < result.Removed[j].Name
	})
	sort.Slice(result.Upgraded, func(i, j int) bool {
		return result.Upgraded[i].Package.Name < result.Upgraded[j].Package.Name
	})
	sort.Slice(result.Downgraded, func(i, j int) bool {
		return result.Downgraded[i].Package.Name < result.Downgraded[j].Package.Name
	})

	return result
}

func compareLayers(oldLayers, newLayers []config.ImageLayer) config.LayerDiff {
	result := config.LayerDiff{
		OldLayerCount: len(oldLayers),
		NewLayerCount: len(newLayers),
	}

	oldFileSets := make([]map[string]bool, len(oldLayers))
	for i, layer := range oldLayers {
		oldFileSets[i] = make(map[string]bool)
		for _, f := range layer.AddedFiles {
			oldFileSets[i][f] = true
		}
		for _, f := range layer.ModifiedFiles {
			oldFileSets[i][f] = true
		}
	}

	newFileSets := make([]map[string]bool, len(newLayers))
	for i, layer := range newLayers {
		newFileSets[i] = make(map[string]bool)
		for _, f := range layer.AddedFiles {
			newFileSets[i][f] = true
		}
		for _, f := range layer.ModifiedFiles {
			newFileSets[i][f] = true
		}
	}

	maxLayers := len(oldLayers)
	if len(newLayers) > maxLayers {
		maxLayers = len(newLayers)
	}

	for i := 0; i < maxLayers; i++ {
		change := config.LayerChange{Index: i}

		if i < len(oldLayers) && i < len(newLayers) {
			change.OldFileCount = len(oldFileSets[i])
			change.NewFileCount = len(newFileSets[i])

			for f := range newFileSets[i] {
				if !oldFileSets[i][f] {
					change.AddedFiles = append(change.AddedFiles, f)
				}
			}
			for f := range oldFileSets[i] {
				if !newFileSets[i][f] {
					change.RemovedFiles = append(change.RemovedFiles, f)
				}
			}

			if len(change.AddedFiles) == 0 && len(change.RemovedFiles) == 0 {
				change.ChangeType = "unchanged"
			} else {
				change.ChangeType = "modified"
			}
		} else if i < len(newLayers) {
			change.NewFileCount = len(newFileSets[i])
			change.ChangeType = "added"
			for f := range newFileSets[i] {
				change.AddedFiles = append(change.AddedFiles, f)
			}
		} else {
			change.OldFileCount = len(oldFileSets[i])
			change.ChangeType = "removed"
			for f := range oldFileSets[i] {
				change.RemovedFiles = append(change.RemovedFiles, f)
			}
		}

		sort.Strings(change.AddedFiles)
		sort.Strings(change.RemovedFiles)
		result.LayerChanges = append(result.LayerChanges, change)
	}

	return result
}

func compareCompliance(oldIssues, newIssues []config.ComplianceIssue) config.ComplianceDiff {
	oldMap := make(map[string]config.ComplianceIssue)
	for _, i := range oldIssues {
		oldMap[i.RuleID] = i
	}

	newMap := make(map[string]config.ComplianceIssue)
	for _, i := range newIssues {
		newMap[i.RuleID] = i
	}

	var result config.ComplianceDiff

	for key, issue := range newMap {
		if _, exists := oldMap[key]; exists {
			result.Unchanged = append(result.Unchanged, issue)
		} else {
			result.Added = append(result.Added, issue)
		}
	}

	for key, issue := range oldMap {
		if _, exists := newMap[key]; !exists {
			result.Removed = append(result.Removed, issue)
		}
	}

	return result
}

func HasNewCriticalOrHigh(diff *config.DiffResult) (hasCritical, hasHigh bool) {
	for _, v := range diff.VulnerabilityDiff.Added {
		if v.Severity == config.SeverityCritical {
			hasCritical = true
		}
	}
	return
}

func GetAddedVulnerabilityCounts(diff *config.DiffResult) (critical, high, medium, low int) {
	for _, v := range diff.VulnerabilityDiff.Added {
		switch v.Severity {
		case config.SeverityCritical:
			critical++
		case config.SeverityHigh:
			high++
		case config.SeverityMedium:
			medium++
		case config.SeverityLow:
			low++
		}
	}
	return
}

func GetHighestAddedSeverity(diff *config.DiffResult) config.Severity {
	highest := config.SeverityNone
	severityOrder := map[config.Severity]int{
		config.SeverityCritical: 4,
		config.SeverityHigh:     3,
		config.SeverityMedium:   2,
		config.SeverityLow:      1,
		config.SeverityNone:     0,
	}

	for _, v := range diff.VulnerabilityDiff.Added {
		if severityOrder[v.Severity] > severityOrder[highest] {
			highest = v.Severity
		}
	}
	return highest
}
