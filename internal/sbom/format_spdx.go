package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"imgscan/internal/config"
)

type SPDXDocument struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      SPDXCreation   `json:"creationInfo"`
	Packages          []SPDXPackage  `json:"packages"`
	Relationships     []SPDXRel      `json:"relationships"`
	ExternalDocumentRefs []interface{} `json:"externalDocumentRefs,omitempty"`
}

type SPDXCreation struct {
	Created  string          `json:"created"`
	Creators []SPDXCreator   `json:"creators"`
	LicenseListVersion string `json:"licenseListVersion"`
}

type SPDXCreator struct {
	Creator string `json:"creator"`
}

type SPDXPackage struct {
	SPDXID           string         `json:"SPDXID"`
	Name             string         `json:"name"`
	VersionInfo      string         `json:"versionInfo,omitempty"`
	PackageFileName  string         `json:"packageFileName,omitempty"`
	Supplier         string         `json:"supplier,omitempty"`
	Originator       string         `json:"originator,omitempty"`
	DownloadLocation string         `json:"downloadLocation"`
	FilesAnalyzed    bool           `json:"filesAnalyzed"`
	LicenseConcluded string         `json:"licenseConcluded"`
	LicenseDeclared  string         `json:"licenseDeclared"`
	CopyrightText    string         `json:"copyrightText"`
	Checksums        []SPDXChecksum `json:"checksums,omitempty"`
	ExternalRefs     []SPDXExtRef   `json:"externalRefs,omitempty"`
	PackageVerificationCode *SPDXVerification `json:"packageVerificationCode,omitempty"`
}

type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type SPDXVerification struct {
	PackageVerificationCodeValue string `json:"packageVerificationCodeValue"`
}

type SPDXExtRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type SPDXRel struct {
	SPDXElementID          string `json:"spdxElementId"`
	RelationshipType       string `json:"relationshipType"`
	RelatedSPDXElement     string `json:"relatedSpdxElement"`
}

func RenderSPDXJSON(doc *SBOMDocument) ([]byte, error) {
	spdxDoc := convertToSPDX(doc)
	return json.MarshalIndent(spdxDoc, "", "  ")
}

func RenderSPDXTV(doc *SBOMDocument) ([]byte, error) {
	spdxDoc := convertToSPDX(doc)
	var sb strings.Builder

	sb.WriteString("SPDXVersion: " + spdxDoc.SPDXVersion + "\n")
	sb.WriteString("DataLicense: " + spdxDoc.DataLicense + "\n")
	sb.WriteString("SPDXID: " + spdxDoc.SPDXID + "\n")
	sb.WriteString("DocumentName: " + spdxDoc.Name + "\n")
	sb.WriteString("DocumentNamespace: " + spdxDoc.DocumentNamespace + "\n")
	sb.WriteString("Creator: Tool: imgscan\n")
	sb.WriteString("Created: " + spdxDoc.CreationInfo.Created + "\n")
	sb.WriteString("LicenseListVersion: " + spdxDoc.CreationInfo.LicenseListVersion + "\n")
	sb.WriteString("\n")

	for _, pkg := range spdxDoc.Packages {
		sb.WriteString("##### Package: " + pkg.Name + "\n")
		sb.WriteString("PackageName: " + pkg.Name + "\n")
		sb.WriteString("SPDXID: " + pkg.SPDXID + "\n")
		if pkg.VersionInfo != "" {
			sb.WriteString("PackageVersion: " + pkg.VersionInfo + "\n")
		}
		if pkg.Supplier != "" {
			sb.WriteString("PackageSupplier: " + pkg.Supplier + "\n")
		}
		if pkg.Originator != "" {
			sb.WriteString("PackageOriginator: " + pkg.Originator + "\n")
		}
		sb.WriteString("PackageDownloadLocation: " + pkg.DownloadLocation + "\n")
		sb.WriteString("FilesAnalyzed: false\n")
		sb.WriteString("PackageLicenseConcluded: " + pkg.LicenseConcluded + "\n")
		sb.WriteString("PackageLicenseDeclared: " + pkg.LicenseDeclared + "\n")
		sb.WriteString("PackageCopyrightText: NOASSERTION\n")
		for _, cs := range pkg.Checksums {
			sb.WriteString("PackageChecksum: " + cs.Algorithm + ": " + cs.ChecksumValue + "\n")
		}
		for _, ref := range pkg.ExternalRefs {
			sb.WriteString("ExternalRef: " + ref.ReferenceCategory + " " + ref.ReferenceType + " " + ref.ReferenceLocator + "\n")
		}
		sb.WriteString("\n")
	}

	for _, rel := range spdxDoc.Relationships {
		sb.WriteString("Relationship: " + rel.SPDXElementID + " " + rel.RelationshipType + " " + rel.RelatedSPDXElement + "\n")
	}

	return []byte(sb.String()), nil
}

func convertToSPDX(doc *SBOMDocument) *SPDXDocument {
	spdxDoc := &SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              doc.Name,
		DocumentNamespace: doc.Namespace,
		CreationInfo: SPDXCreation{
			Created:  doc.Created,
			LicenseListVersion: "3.21",
			Creators: []SPDXCreator{
				{Creator: "Tool: imgscan-1.0.0"},
			},
		},
	}

	if spdxDoc.CreationInfo.Created == "" {
		spdxDoc.CreationInfo.Created = time.Now().UTC().Format(time.RFC3339)
	}

	spdxDoc.Packages = make([]SPDXPackage, 0, len(doc.Packages))
	for _, pkg := range doc.Packages {
		spdxPkg := SPDXPackage{
			SPDXID:           "SPDXRef-Package-" + sanitizeID(pkg.ID),
			Name:             pkg.Name,
			VersionInfo:      pkg.Version,
			Supplier:         formatEntity(pkg.Supplier),
			DownloadLocation: pkg.DownloadLocation,
			FilesAnalyzed:    false,
			LicenseConcluded: pkg.LicenseConcluded,
			LicenseDeclared:  pkg.LicenseDeclared,
			CopyrightText:    "NOASSERTION",
		}

		if spdxPkg.LicenseConcluded == "" {
			spdxPkg.LicenseConcluded = "NOASSERTION"
		}
		if spdxPkg.LicenseDeclared == "" {
			spdxPkg.LicenseDeclared = "NOASSERTION"
		}
		if spdxPkg.DownloadLocation == "" {
			spdxPkg.DownloadLocation = "NOASSERTION"
		}

		if pkg.SHA256 != "" {
			spdxPkg.Checksums = append(spdxPkg.Checksums, SPDXChecksum{
				Algorithm:     "SHA256",
				ChecksumValue: pkg.SHA256,
			})
		}

		extRefs := buildSPDXExternalRefs(pkg)
		spdxPkg.ExternalRefs = extRefs

		spdxDoc.Packages = append(spdxDoc.Packages, spdxPkg)
	}

	spdxDoc.Relationships = make([]SPDXRel, 0)
	for _, pkg := range doc.Packages {
		pkgRef := "SPDXRef-Package-" + sanitizeID(pkg.ID)
		spdxDoc.Relationships = append(spdxDoc.Relationships, SPDXRel{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: pkgRef,
		})

		for i, depName := range pkg.Provenance.DependencyPath {
			if i == 0 {
				continue
			}
			depRef := "SPDXRef-Package-" + sanitizeID(depName)
			spdxDoc.Relationships = append(spdxDoc.Relationships, SPDXRel{
				SPDXElementID:      pkgRef,
				RelationshipType:   "DEPENDS_ON",
				RelatedSPDXElement: depRef,
			})
		}
	}

	return spdxDoc
}

func buildSPDXExternalRefs(pkg SBOMPackage) []SPDXExtRef {
	var refs []SPDXExtRef

	refs = append(refs, SPDXExtRef{
		ReferenceCategory: "OTHER",
		ReferenceType:     "internalPackageId",
		ReferenceLocator:  pkg.ID,
	})

	refs = append(refs, SPDXExtRef{
		ReferenceCategory: "OTHER",
		ReferenceType:     "internalPackageType",
		ReferenceLocator:  string(pkg.PackageType),
	})

	purl := generatePURL(pkg)
	if purl != "" {
		refs = append(refs, SPDXExtRef{
			ReferenceCategory: "PACKAGE_MANAGER",
			ReferenceType:     "purl",
			ReferenceLocator:  purl,
		})
	}

	for _, vuln := range pkg.Vulnerabilities {
		if vuln.CVE != "" {
			refs = append(refs, SPDXExtRef{
				ReferenceCategory: "SECURITY",
				ReferenceType:     "cpe23Type",
				ReferenceLocator:  fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", pkg.Name, pkg.Version),
			})
			break
		}
	}

	if pkg.Provenance.InstallMethod != "" {
		refs = append(refs, SPDXExtRef{
			ReferenceCategory: "OTHER",
			ReferenceType:     "provenance",
			ReferenceLocator:  FormatProvenance(pkg.Provenance),
		})
	}

	return refs
}

func formatEntity(s string) string {
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "Organization:") && !strings.HasPrefix(s, "Person:") && !strings.HasPrefix(s, "NOASSERTION") {
		return "Organization: " + s
	}
	return s
}

func sanitizeID(id string) string {
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			return r
		}
		return '-'
	}, id)
	return result
}

func generatePURL(pkg SBOMPackage) string {
	var purlType string
	var namespace string

	switch pkg.PackageType {
	case config.PkgTypeDeb:
		purlType = "deb"
		namespace = "debian"
	case config.PkgTypeRPM:
		purlType = "rpm"
		namespace = "centos"
	case config.PkgTypeAPK:
		purlType = "apk"
		namespace = "alpine"
	case config.PkgTypePip:
		purlType = "pypi"
	case config.PkgTypeNpm:
		purlType = "npm"
	case config.PkgTypeGo:
		purlType = "golang"
	case config.PkgTypeMaven:
		purlType = "maven"
	default:
		return ""
	}

	name := pkg.Name
	if pkg.PackageType == config.PkgTypeMaven {
		parts := strings.SplitN(pkg.Name, ":", 2)
		if len(parts) == 2 {
			namespace = parts[0]
			name = parts[1]
		}
	}

	if namespace != "" {
		return fmt.Sprintf("pkg:%s/%s/%s@%s", purlType, namespace, name, pkg.Version)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", purlType, name, pkg.Version)
}
