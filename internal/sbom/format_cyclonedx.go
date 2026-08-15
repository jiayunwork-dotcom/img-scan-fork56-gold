package sbom

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"imgscan/internal/config"
)

type CycloneDX struct {
	XMLName         xml.Name          `xml:"bom" json:"-"`
	XMLNS           string            `xml:"xmlns,attr" json:"-"`
	Version         int               `xml:"version,attr" json:"version"`
	SerialNumber    string            `xml:"serialNumber,attr" json:"serialNumber"`
	SchemaVersion   string            `xml:"-" json:"$schema,omitempty"`
	BOMFormat       string            `xml:"-" json:"bomFormat,omitempty"`
	SpecVersion     string            `xml:"-" json:"specVersion,omitempty"`
	Metadata        *CDXMetadata      `xml:"metadata" json:"metadata,omitempty"`
	Components      []CDXComponent    `xml:"components>component" json:"components,omitempty"`
	Dependencies    *CDXDependencies  `xml:"dependencies" json:"dependencies,omitempty"`
	Vulnerabilities *CDXVulns         `xml:"vulnerabilities" json:"vulnerabilities,omitempty"`
}

type CDXMetadata struct {
	Timestamp  string       `xml:"timestamp" json:"timestamp"`
	Tools      *CDXTools    `xml:"tools" json:"tools,omitempty"`
	Component  *CDXComponent `xml:"component" json:"component,omitempty"`
}

type CDXTools struct {
	Tool []CDXTool `xml:"tool" json:"-" json2:"tool,omitempty"`
}

type CDXTool struct {
	Vendor  string `xml:"vendor" json:"vendor,omitempty"`
	Name    string `xml:"name" json:"name"`
	Version string `xml:"version" json:"version"`
}

type CDXComponent struct {
	BOMRef           string           `xml:"bom-ref,attr" json:"bom-ref"`
	Type             string           `xml:"type,attr" json:"type"`
	Name             string           `xml:"name" json:"name"`
	Version          string           `xml:"version" json:"version,omitempty"`
	Group            string           `xml:"group" json:"group,omitempty"`
	Publisher        string           `xml:"publisher" json:"publisher,omitempty"`
	Description      string           `xml:"description" json:"description,omitempty"`
	Scope            string           `xml:"scope" json:"scope,omitempty"`
	Licenses         *CDXLicenses     `xml:"licenses" json:"licenses,omitempty"`
	Hashes           *CDXHashes       `xml:"hashes" json:"hashes,omitempty"`
	PURL             string           `xml:"purl" json:"purl,omitempty"`
	ExternalReferences *CDXExtRefs    `xml:"externalReferences" json:"externalReferences,omitempty"`
	Properties       *CDXProperties   `xml:"properties" json:"properties,omitempty"`
}

type CDXLicenses struct {
	License []CDXLicense `xml:"license" json:"license"`
}

type CDXLicense struct {
	ID   string `xml:"id" json:"id,omitempty"`
	Name string `xml:"name" json:"name,omitempty"`
	URL  string `xml:"url" json:"url,omitempty"`
}

type CDXHashes struct {
	Hash []CDXHash `xml:"hash" json:"hash"`
}

type CDXHash struct {
	Algorithm string `xml:"alg,attr" json:"alg"`
	Value     string `xml:",chardata" json:"content"`
}

type CDXExtRefs struct {
	Reference []CDXExtRef `xml:"reference" json:"reference"`
}

type CDXExtRef struct {
	Type string `xml:"type" json:"type"`
	URL  string `xml:"url" json:"url"`
}

type CDXProperties struct {
	Property []CDXProperty `xml:"property" json:"property"`
}

type CDXProperty struct {
	Name  string `xml:"name,attr" json:"name"`
	Value string `xml:",chardata" json:"value"`
}

type CDXDependencies struct {
	Dependency []CDXDependency `xml:"dependency" json:"dependency"`
}

type CDXDependency struct {
	Ref       string   `xml:"ref,attr" json:"ref"`
	DependsOn []string `xml:"dependsOn>dependency" json:"dependsOn,omitempty"`
}

type CDXVulns struct {
	Vulnerability []CDXVulnerability `xml:"vulnerability" json:"vulnerability"`
}

type CDXVulnerability struct {
	Ref         string        `xml:"ref,attr" json:"ref"`
	ID          string        `xml:"id" json:"id"`
	Source      *CDXSource    `xml:"source" json:"source,omitempty"`
	Ratings     *CDXRatings   `xml:"ratings" json:"ratings,omitempty"`
	Description string        `xml:"description" json:"description,omitempty"`
	Advisories  *CDXAdvisories `xml:"advisories" json:"advisories,omitempty"`
}

type CDXSource struct {
	Name string `xml:"name" json:"name"`
	URL  string `xml:"url" json:"url,omitempty"`
}

type CDXRatings struct {
	Rating []CDXRating `xml:"rating" json:"rating"`
}

type CDXRating struct {
	Severity    string  `xml:"severity" json:"severity"`
	Score       float64 `xml:"score" json:"score,omitempty"`
	Method      string  `xml:"method" json:"method,omitempty"`
	Vector      string  `xml:"vector" json:"vector,omitempty"`
}

type CDXAdvisories struct {
	Advisory []CDXAdvisory `xml:"advisory" json:"advisory"`
}

type CDXAdvisory struct {
	Title string `xml:"title" json:"title"`
	URL   string `xml:"url" json:"url"`
}

func RenderCycloneDXJSON(doc *SBOMDocument) ([]byte, error) {
	cdx := convertToCycloneDX(doc)
	cdx.XMLNS = ""
	cdx.SchemaVersion = "http://cyclonedx.org/schema/bom-1.5.schema.json"
	cdx.BOMFormat = "CycloneDX"
	cdx.SpecVersion = "1.5"

	type CDXJSON struct {
		SchemaVersion   string          `json:"$schema"`
		BOMFormat       string          `json:"bomFormat"`
		SpecVersion     string          `json:"specVersion"`
		Version         int             `json:"version"`
		SerialNumber    string          `json:"serialNumber"`
		Metadata        *CDXMetadata    `json:"metadata"`
		Components      []CDXComponent  `json:"components"`
		Dependencies    []CDXDependency `json:"dependencies,omitempty"`
		Vulnerabilities []CDXVulnerability `json:"vulnerabilities,omitempty"`
	}

	jsonDoc := CDXJSON{
		SchemaVersion: cdx.SchemaVersion,
		BOMFormat:     cdx.BOMFormat,
		SpecVersion:   cdx.SpecVersion,
		Version:       cdx.Version,
		SerialNumber:  cdx.SerialNumber,
		Metadata:      cdx.Metadata,
		Components:    cdx.Components,
	}

	if cdx.Dependencies != nil {
		jsonDoc.Dependencies = cdx.Dependencies.Dependency
	}
	if cdx.Vulnerabilities != nil {
		jsonDoc.Vulnerabilities = cdx.Vulnerabilities.Vulnerability
	}

	return json.MarshalIndent(jsonDoc, "", "  ")
}

func RenderCycloneDXXML(doc *SBOMDocument) ([]byte, error) {
	cdx := convertToCycloneDX(doc)
	cdx.XMLNS = "http://cyclonedx.org/schema/bom/1.5"

	output, err := xml.MarshalIndent(cdx, "", "  ")
	if err != nil {
		return nil, err
	}

	return []byte(xml.Header + string(output)), nil
}

func convertToCycloneDX(doc *SBOMDocument) *CycloneDX {
	cdx := &CycloneDX{
		Version:      1,
		SerialNumber: fmt.Sprintf("urn:uuid:%s", strings.TrimPrefix(doc.Namespace, "https://imgscan.sbom/")),
		Metadata: &CDXMetadata{
			Timestamp: doc.Created,
			Tools: &CDXTools{
				Tool: []CDXTool{
					{Vendor: "imgscan", Name: "imgscan", Version: "1.0.0"},
				},
			},
		},
	}

	if cdx.Metadata.Timestamp == "" {
		cdx.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	if doc.ImageName != "" {
		cdx.Metadata.Component = &CDXComponent{
			BOMRef: "image-" + sanitizeID(doc.ImageName),
			Type:   "container",
			Name:   doc.ImageName,
		}
	}

	cdx.Components = make([]CDXComponent, 0, len(doc.Packages))
	for _, pkg := range doc.Packages {
		component := CDXComponent{
			BOMRef:     sanitizeID(pkg.ID),
			Type:       componentType(pkg.PackageType),
			Name:       pkg.Name,
			Version:    pkg.Version,
			Publisher:  pkg.Supplier,
			Scope:      "required",
			PURL:       generatePURL(pkg),
		}

		if pkg.PackageType == config.PkgTypeMaven {
			parts := strings.SplitN(pkg.Name, ":", 2)
			if len(parts) == 2 {
				component.Group = parts[0]
				component.Name = parts[1]
			}
		}

		if pkg.LicenseConcluded != "" && pkg.LicenseConcluded != "NOASSERTION" {
			licenses := parseLicensesForCDX(pkg.LicenseConcluded)
			if len(licenses) > 0 {
				component.Licenses = &CDXLicenses{License: licenses}
			}
		}

		if pkg.SHA256 != "" {
			component.Hashes = &CDXHashes{
				Hash: []CDXHash{
					{Algorithm: "SHA-256", Value: pkg.SHA256},
				},
			}
		}

		var extRefs []CDXExtRef
		for _, vuln := range pkg.Vulnerabilities {
			if vuln.URL != "" {
				extRefs = append(extRefs, CDXExtRef{
					Type: "vulnerability",
					URL:  vuln.URL,
				})
			}
		}

		if doc.Signature.HasSLSAProvenance {
			extRefs = append(extRefs, CDXExtRef{
				Type: "attestation",
				URL:  doc.Signature.AttestationRaw,
			})
		}

		if len(extRefs) > 0 {
			component.ExternalReferences = &CDXExtRefs{Reference: extRefs}
		}

		var properties []CDXProperty
		properties = append(properties, CDXProperty{
			Name:  "imgscan:internal:id",
			Value: pkg.ID,
		})
		properties = append(properties, CDXProperty{
			Name:  "imgscan:internal:type",
			Value: string(pkg.PackageType),
		})
		properties = append(properties, CDXProperty{
			Name:  "imgscan:provenance:layer",
			Value: fmt.Sprintf("%d", pkg.Provenance.LayerIndex),
		})
		properties = append(properties, CDXProperty{
			Name:  "imgscan:provenance:method",
			Value: pkg.Provenance.InstallMethod,
		})
		properties = append(properties, CDXProperty{
			Name:  "imgscan:provenance:direct",
			Value: fmt.Sprintf("%v", pkg.Provenance.IsDirect),
		})
		if len(pkg.Provenance.DependencyPath) > 0 {
			properties = append(properties, CDXProperty{
				Name:  "imgscan:provenance:path",
				Value: FormatDependencyPath(pkg.Provenance.DependencyPath),
			})
		}
		if pkg.RiskScore > 0 {
			properties = append(properties, CDXProperty{
				Name:  "imgscan:risk:score",
				Value: fmt.Sprintf("%.1f", pkg.RiskScore),
			})
		}
		component.Properties = &CDXProperties{Property: properties}

		cdx.Components = append(cdx.Components, component)
	}

	deps := buildCDXDependencies(doc)
	if len(deps) > 0 {
		cdx.Dependencies = &CDXDependencies{Dependency: deps}
	}

	vulns := buildCDXVulnerabilities(doc)
	if len(vulns) > 0 {
		cdx.Vulnerabilities = &CDXVulns{Vulnerability: vulns}
	}

	return cdx
}

func componentType(pkgType config.PackageType) string {
	switch pkgType {
	case config.PkgTypeDeb, config.PkgTypeRPM, config.PkgTypeAPK:
		return "operating-system"
	case config.PkgTypePip, config.PkgTypeNpm, config.PkgTypeGo, config.PkgTypeMaven:
		return "library"
	default:
		return "library"
	}
}

func parseLicensesForCDX(licenseStr string) []CDXLicense {
	var licenses []CDXLicense

	if strings.Contains(licenseStr, " OR ") {
		parts := strings.Split(licenseStr, " OR ")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			licenses = append(licenses, CDXLicense{ID: p})
		}
		return licenses
	}

	if strings.Contains(licenseStr, " AND ") {
		parts := strings.Split(licenseStr, " AND ")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			licenses = append(licenses, CDXLicense{ID: p})
		}
		return licenses
	}

	if strings.Contains(licenseStr, " WITH ") {
		licenses = append(licenses, CDXLicense{ID: licenseStr})
		return licenses
	}

	licenses = append(licenses, CDXLicense{ID: licenseStr})
	return licenses
}

func buildCDXDependencies(doc *SBOMDocument) []CDXDependency {
	pkgMap := make(map[string][]string)

	for _, pkg := range doc.Packages {
		pkgRef := sanitizeID(pkg.ID)
		if pkg.Provenance.DependencyPath != nil {
			for i, depName := range pkg.Provenance.DependencyPath {
				if i == 0 {
					continue
				}
				pkgMap[pkgRef] = append(pkgMap[pkgRef], sanitizeID(depName))
			}
		}

		for _, rel := range doc.Relationships {
			if rel.SourceID == pkg.ID {
				pkgMap[pkgRef] = append(pkgMap[pkgRef], sanitizeID(rel.TargetID))
			}
		}
	}

	var deps []CDXDependency
	for ref, dependsOn := range pkgMap {
		if len(dependsOn) > 0 {
			deps = append(deps, CDXDependency{
				Ref:       ref,
				DependsOn: dependsOn,
			})
		}
	}

	return deps
}

func buildCDXVulnerabilities(doc *SBOMDocument) []CDXVulnerability {
	var vulns []CDXVulnerability

	for _, pkg := range doc.Packages {
		for _, v := range pkg.Vulnerabilities {
			cdxVuln := CDXVulnerability{
				Ref: sanitizeID(pkg.ID),
				ID:  v.CVE,
				Source: &CDXSource{
					Name: "OSV",
					URL:  fmt.Sprintf("https://osv.dev/vulnerability/%s", v.ID),
				},
				Ratings: &CDXRatings{
					Rating: []CDXRating{
						{
							Severity: strings.ToLower(string(v.Severity)),
							Score:    v.CVSS,
							Method:   "CVSSv31",
						},
					},
				},
				Description: v.Description,
			}

			if v.URL != "" {
				cdxVuln.Advisories = &CDXAdvisories{
					Advisory: []CDXAdvisory{
						{Title: v.CVE, URL: v.URL},
					},
				}
			} else if v.CVE != "" {
				cdxVuln.Advisories = &CDXAdvisories{
					Advisory: []CDXAdvisory{
						{Title: v.CVE, URL: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CVE)},
					},
				}
			}

			vulns = append(vulns, cdxVuln)
		}
	}

	return vulns
}
