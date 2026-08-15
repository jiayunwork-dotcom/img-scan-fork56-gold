package sbom

import (
	"encoding/json"
	"fmt"
	"strings"

	"imgscan/internal/config"
)

type IncrementalComparator struct {
	current  *SBOMDocument
	baseline *SBOMDocument
}

func NewIncrementalComparator(current *SBOMDocument, baseline *SBOMDocument) *IncrementalComparator {
	return &IncrementalComparator{
		current:  current,
		baseline: baseline,
	}
}

func (ic *IncrementalComparator) Compare() IncrementalResult {
	result := IncrementalResult{}

	if ic.baseline == nil {
		result.AddedPackages = ic.current.Packages
		for i := range ic.current.Packages {
			result.Patches = append(result.Patches, JSONPatchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/packages/%d", i),
				Value: ic.current.Packages[i],
			})
		}
		return result
	}

	currentMap := make(map[string]SBOMPackage)
	for _, pkg := range ic.current.Packages {
		currentMap[pkg.ID] = pkg
	}

	baselineMap := make(map[string]SBOMPackage)
	for _, pkg := range ic.baseline.Packages {
		baselineMap[pkg.ID] = pkg
	}

	for id, currentPkg := range currentMap {
		if baselinePkg, exists := baselineMap[id]; exists {
			if currentPkg.Version != baselinePkg.Version {
				result.VersionChanges = append(result.VersionChanges, PackageChange{
					Package:   currentPkg,
					OldVersion: baselinePkg.Version,
					NewVersion: currentPkg.Version,
				})
				result.Patches = append(result.Patches, JSONPatchOp{
					Op:    "replace",
					Path:  fmt.Sprintf("/packages/%s/version", sanitizeJSONPath(id)),
					Value: currentPkg.Version,
				})
			}

			if currentPkg.LicenseConcluded != baselinePkg.LicenseConcluded {
				result.LicenseChanges = append(result.LicenseChanges, LicenseChange{
					PackageName: currentPkg.Name,
					OldLicense:  baselinePkg.LicenseConcluded,
					NewLicense:  currentPkg.LicenseConcluded,
				})
				result.Patches = append(result.Patches, JSONPatchOp{
					Op:    "replace",
					Path:  fmt.Sprintf("/packages/%s/licenseConcluded", sanitizeJSONPath(id)),
					Value: currentPkg.LicenseConcluded,
				})
			}
		} else {
			result.AddedPackages = append(result.AddedPackages, currentPkg)
			result.Patches = append(result.Patches, JSONPatchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/packages/%s", sanitizeJSONPath(id)),
				Value: currentPkg,
			})
		}
	}

	for id, baselinePkg := range baselineMap {
		if _, exists := currentMap[id]; !exists {
			result.RemovedPackages = append(result.RemovedPackages, baselinePkg)
			result.Patches = append(result.Patches, JSONPatchOp{
				Op:   "remove",
				Path: fmt.Sprintf("/packages/%s", sanitizeJSONPath(id)),
			})
		}
	}

	return result
}

func LoadBaseline(data []byte) (*SBOMDocument, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return nil, fmt.Errorf("failed to parse baseline: %w", err)
	}

	if _, ok := rawMap["spdxVersion"]; ok {
		return loadBaselineFromSPDX(data)
	}

	if _, ok := rawMap["bomFormat"]; ok {
		return loadBaselineFromCycloneDX(data)
	}

	return loadBaselineFromInternal(data)
}

func loadBaselineFromInternal(data []byte) (*SBOMDocument, error) {
	var doc SBOMDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse internal format baseline: %w", err)
	}

	for i := range doc.Packages {
		if doc.Packages[i].ID == "" {
			doc.Packages[i].ID = PkgID(doc.Packages[i].Name, doc.Packages[i].Version, doc.Packages[i].PackageType)
		}
	}

	return &doc, nil
}

func loadBaselineFromSPDX(data []byte) (*SBOMDocument, error) {
	var spdxDoc SPDXDocument
	if err := json.Unmarshal(data, &spdxDoc); err != nil {
		return nil, fmt.Errorf("failed to parse SPDX baseline: %w", err)
	}

	doc := &SBOMDocument{
		Name:            spdxDoc.Name,
		Namespace:       spdxDoc.DocumentNamespace,
		Created:         spdxDoc.CreationInfo.Created,
	}

	for _, spdxPkg := range spdxDoc.Packages {
		pkg := SBOMPackage{
			Name:             spdxPkg.Name,
			Version:          spdxPkg.VersionInfo,
			Supplier:         parseSupplier(spdxPkg.Supplier),
			LicenseConcluded: spdxPkg.LicenseConcluded,
			LicenseDeclared:  spdxPkg.LicenseDeclared,
			DownloadLocation: spdxPkg.DownloadLocation,
		}

		for _, cs := range spdxPkg.Checksums {
			if cs.Algorithm == "SHA256" {
				pkg.SHA256 = cs.ChecksumValue
			}
		}

		for _, ref := range spdxPkg.ExternalRefs {
			if ref.ReferenceType == "internalPackageId" {
				pkg.ID = ref.ReferenceLocator
			}
			if ref.ReferenceType == "internalPackageType" {
				pkg.PackageType = config.PackageType(ref.ReferenceLocator)
			}
		}

		if pkg.ID == "" {
			pkg.ID = PkgID(pkg.Name, pkg.Version, pkg.PackageType)
		}

		doc.Packages = append(doc.Packages, pkg)
	}

	return doc, nil
}

func loadBaselineFromCycloneDX(data []byte) (*SBOMDocument, error) {
	type CDXLicenseWrapper struct {
		License struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"license"`
	}

	type CDXHash struct {
		Algorithm string `json:"alg"`
		Value     string `json:"content"`
	}

	type CDXProperty struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}

	type CDXPackage struct {
		Name        string                 `json:"name"`
		Version     string                 `json:"version"`
		Publisher   string                 `json:"publisher"`
		PURL        string                 `json:"purl"`
		BOMRef      string                 `json:"bom-ref"`
		Licenses    []CDXLicenseWrapper    `json:"licenses"`
		Hashes      []CDXHash              `json:"hashes"`
		Properties  []CDXProperty          `json:"properties"`
	}

	type CDXDoc struct {
		Metadata struct {
			Timestamp string `json:"timestamp"`
		} `json:"metadata"`
		Components []CDXPackage `json:"components"`
	}

	var cdxDoc CDXDoc
	if err := json.Unmarshal(data, &cdxDoc); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX baseline: %w", err)
	}

	doc := &SBOMDocument{
		Created: cdxDoc.Metadata.Timestamp,
	}

	for _, cdxPkg := range cdxDoc.Components {
		pkg := SBOMPackage{
			Name:     cdxPkg.Name,
			Version:  cdxPkg.Version,
			Supplier: cdxPkg.Publisher,
		}

		for _, lic := range cdxPkg.Licenses {
			if lic.License.ID != "" {
				pkg.LicenseConcluded = lic.License.ID
				pkg.LicenseDeclared = lic.License.ID
			}
		}

		for _, h := range cdxPkg.Hashes {
			if h.Algorithm == "SHA-256" {
				pkg.SHA256 = h.Value
			}
		}

		for _, prop := range cdxPkg.Properties {
			if prop.Name == "imgscan:internal:id" {
				pkg.ID = prop.Value
			}
			if prop.Name == "imgscan:internal:type" {
				pkg.PackageType = config.PackageType(prop.Value)
			}
		}

		if pkg.ID == "" {
			pkg.ID = PkgID(pkg.Name, pkg.Version, pkg.PackageType)
		}

		doc.Packages = append(doc.Packages, pkg)
	}

	return doc, nil
}

func parseSupplier(supplier string) string {
	supplier = strings.TrimPrefix(supplier, "Organization: ")
	supplier = strings.TrimPrefix(supplier, "Person: ")
	return strings.TrimSpace(supplier)
}

func RenderIncrementalResult(result IncrementalResult) ([]byte, error) {
	type IncrementalReport struct {
		Summary struct {
			AddedPackages   int `json:"added_packages"`
			RemovedPackages int `json:"removed_packages"`
			VersionChanges  int `json:"version_changes"`
			LicenseChanges  int `json:"license_changes"`
		} `json:"summary"`
		AddedPackages   []string        `json:"added_packages_detail,omitempty"`
		RemovedPackages []string        `json:"removed_packages_detail,omitempty"`
		VersionChanges  []string        `json:"version_changes_detail,omitempty"`
		LicenseChanges  []string        `json:"license_changes_detail,omitempty"`
		Patches         []JSONPatchOp   `json:"patches"`
	}

	report := IncrementalReport{}
	report.Summary.AddedPackages = len(result.AddedPackages)
	report.Summary.RemovedPackages = len(result.RemovedPackages)
	report.Summary.VersionChanges = len(result.VersionChanges)
	report.Summary.LicenseChanges = len(result.LicenseChanges)

	for _, pkg := range result.AddedPackages {
		report.AddedPackages = append(report.AddedPackages, fmt.Sprintf("%s %s", pkg.Name, pkg.Version))
	}
	for _, pkg := range result.RemovedPackages {
		report.RemovedPackages = append(report.RemovedPackages, fmt.Sprintf("%s %s", pkg.Name, pkg.Version))
	}
	for _, change := range result.VersionChanges {
		report.VersionChanges = append(report.VersionChanges, fmt.Sprintf("%s: %s -> %s", change.Package.Name, change.OldVersion, change.NewVersion))
	}
	for _, change := range result.LicenseChanges {
		report.LicenseChanges = append(report.LicenseChanges, fmt.Sprintf("%s: %s -> %s", change.PackageName, change.OldLicense, change.NewLicense))
	}

	report.Patches = result.Patches

	return json.MarshalIndent(report, "", "  ")
}

func sanitizeJSONPath(id string) string {
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, id)
	return result
}
