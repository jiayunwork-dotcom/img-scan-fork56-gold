package sbom

import (
	"imgscan/internal/config"
)

type SBOMFormat string

const (
	FormatSPDXJSON       SBOMFormat = "spdx-json"
	FormatSPDXTV         SBOMFormat = "spdx-tv"
	FormatCycloneDXJSON  SBOMFormat = "cyclonedx-json"
	FormatCycloneDXXML   SBOMFormat = "cyclonedx-xml"
)

type SBOMDocument struct {
	Name              string
	Namespace         string
	Created           string
	Creators          []Creator
	Packages          []SBOMPackage
	Relationships     []SBOMRelationship
	Vulnerabilities   []SBOMVulnerability
	Signature         SignatureResult
	Reproducibility   ReproducibilityResult
	PolicyResult      PolicyResult
	ImageName         string
	TotalRiskScore    float64
	Ed25519Signature  string `json:"_ed25519_signature,omitempty"`
}

type Creator struct {
	Name string
	Type string
}

type SBOMPackage struct {
	ID               string
	Name             string
	Version          string
	Supplier         string
	LicenseConcluded string
	LicenseDeclared  string
	DownloadLocation string
	SHA256           string
	PackageType      config.PackageType
	PackageFile      string
	Provenance       ProvenanceInfo
	ExternalRefs     []ExternalRef
	RiskScore        float64
	Vulnerabilities  []SBOMVulnerability
	Architecture     string
	SourceInfo       string
}

type ProvenanceInfo struct {
	LayerIndex     int
	InstallMethod  string
	DependencyPath []string
	IsDirect       bool
}

type ExternalRef struct {
	Category string
	Type     string
	Locator  string
}

type SBOMRelationship struct {
	SourceID        string
	RelationshipType string
	TargetID        string
}

type SBOMVulnerability struct {
	PackageID    string
	CVE          string
	ID           string
	Severity     config.Severity
	URL          string
	FixedVersion string
	Description  string
	CVSS         float64
}

type LicenseMatch struct {
	SPDXID       string
	Confidence   float64
	OriginalText string
}

type SignatureResult struct {
	HasCosignSignature bool
	HasSLSAProvenance  bool
	Builder            string
	BuildType          string
	Invocation         string
	UnsignedWarning    string
	AttestationRaw     string
}

type ReproducibilityResult struct {
	GhostPackages    []DiscrepancyItem
	MissingPackages  []DiscrepancyItem
	ConsistencyScore float64
}

type DiscrepancyItem struct {
	Name       string
	Version    string
	Reason     string
	PackageRef string
}

type PolicyResult struct {
	Passed []PolicyRuleResult
	Failed []PolicyRuleResult
}

type PolicyRuleResult struct {
	RuleID   string
	RuleName string
	Passed   bool
	Details  string
}

type Policy struct {
	AllowedLicenses   []string `yaml:"allowed_licenses"`
	DeniedLicenses    []string `yaml:"denied_licenses"`
	RequireSignature  bool     `yaml:"require_signature"`
	MaxRiskScore      float64  `yaml:"max_risk_score"`
	BannedPackages    []string `yaml:"banned_packages"`
}

type IncrementalResult struct {
	AddedPackages    []SBOMPackage
	RemovedPackages  []SBOMPackage
	VersionChanges   []PackageChange
	LicenseChanges   []LicenseChange
	Patches          []JSONPatchOp
}

type PackageChange struct {
	Package   SBOMPackage
	OldVersion string
	NewVersion string
}

type LicenseChange struct {
	PackageName string
	OldLicense  string
	NewLicense  string
}

type JSONPatchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

type DependencyNode struct {
	PackageName string
	Version     string
	DependsOn   []string
}

func PkgID(name, version string, pkgType config.PackageType) string {
	return string(pkgType) + "-" + name + "-" + version
}
