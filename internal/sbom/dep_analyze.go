package sbom

import (
	"fmt"
	"sort"
	"strings"
)

func AnalyzeImpact(doc *SBOMDocument, pkgID string) (*ImpactInfo, error) {
	pkgMap := make(map[string]*SBOMPackage)
	for i := range doc.Packages {
		pkgMap[doc.Packages[i].ID] = &doc.Packages[i]
	}

	pkg, ok := pkgMap[pkgID]
	if !ok {
		return nil, fmt.Errorf("package not found: %s", pkgID)
	}

	reverseDeps := buildReverseDeps(doc)
	info := &ImpactInfo{}

	var collectReverse func(pkgID string, visited map[string]bool)
	collectReverse = func(pid string, visited map[string]bool) {
		if visited[pid] {
			return
		}
		visited[pid] = true
		for _, parentID := range reverseDeps[pid] {
			if !visited[parentID] {
				info.ReverseDeps = append(info.ReverseDeps, parentID)
				collectReverse(parentID, visited)
			}
		}
	}
	collectReverse(pkg.ID, map[string]bool{})
	info.AffectedCount = len(info.ReverseDeps)

	visited := map[string]bool{pkg.ID: true}
	var collectDeps func(pkgID string)
	collectDeps = func(pid string) {
		for _, rel := range doc.Relationships {
			if rel.RelationshipType == "DEPENDS_ON" && rel.SourceID == pid && !visited[rel.TargetID] {
				visited[rel.TargetID] = true
				info.RemoveImpact = append(info.RemoveImpact, rel.TargetID)
				collectDeps(rel.TargetID)
			}
		}
	}
	collectDeps(pkg.ID)

	return info, nil
}

func AnalyzeUpgrades(pkg *SBOMPackage) *UpgradeInfo {
	info := &UpgradeInfo{
		CurrentVersion: pkg.Version,
	}

	fixedVersions := make(map[string][]string)
	for _, vuln := range pkg.Vulnerabilities {
		if vuln.FixedVersion != "" {
			fixedVersions[vuln.FixedVersion] = append(fixedVersions[vuln.FixedVersion], vuln.CVE)
		}
	}

	for version, cves := range fixedVersions {
		info.AvailableVersions = append(info.AvailableVersions, FixedVersionInfo{
			Version:   version,
			FixedCVEs: cves,
		})
	}

	sort.Slice(info.AvailableVersions, func(i, j int) bool {
		return info.AvailableVersions[i].Version > info.AvailableVersions[j].Version
	})

	return info
}

func FormatImpactInfo(doc *SBOMDocument, pkg *SBOMPackage, info *ImpactInfo) string {
	var sb strings.Builder

	pkgMap := make(map[string]*SBOMPackage)
	for i := range doc.Packages {
		pkgMap[doc.Packages[i].ID] = &doc.Packages[i]
	}

	sb.WriteString(fmt.Sprintf("Impact Analysis for %s@%s\n", pkg.Name, pkg.Version))
	sb.WriteString(strings.Repeat("=", 50))
	sb.WriteString("\n\n")

	sb.WriteString("Reverse Dependencies:\n")
	if len(info.ReverseDeps) > 0 {
		for _, depID := range info.ReverseDeps {
			if p, ok := pkgMap[depID]; ok {
				sb.WriteString(fmt.Sprintf("  ← %s@%s\n", p.Name, p.Version))
			} else {
				sb.WriteString(fmt.Sprintf("  ← %s\n", depID))
			}
		}
	} else {
		sb.WriteString("  (no reverse dependencies)\n")
	}

	sb.WriteString(fmt.Sprintf("\nRemoval Impact: %d packages affected\n", info.AffectedCount+len(info.RemoveImpact)))
	if len(info.RemoveImpact) > 0 {
		for _, depID := range info.RemoveImpact {
			if p, ok := pkgMap[depID]; ok {
				sb.WriteString(fmt.Sprintf("  ✗ %s@%s\n", p.Name, p.Version))
			}
		}
	}

	return sb.String()
}

func FormatUpgradeInfo(pkg *SBOMPackage, info *UpgradeInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Available Upgrades for %s\n", pkg.Name))
	sb.WriteString(fmt.Sprintf("Current Version: %s\n", info.CurrentVersion))
	sb.WriteString(strings.Repeat("=", 50))
	sb.WriteString("\n")

	if len(info.AvailableVersions) > 0 {
		for _, v := range info.AvailableVersions {
			sb.WriteString(fmt.Sprintf("  → %s\n", v.Version))
			if len(v.FixedCVEs) > 0 {
				sb.WriteString(fmt.Sprintf("    Fixes: %s\n", strings.Join(v.FixedCVEs, ", ")))
			}
		}
	} else {
		sb.WriteString("  No available upgrade versions found\n")
	}

	return sb.String()
}
