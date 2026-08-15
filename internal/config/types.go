package config

type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityNone     Severity = "None"
)

type ImageInputType string

const (
	InputTypeTar    ImageInputType = "tar"
	InputTypeOCI    ImageInputType = "oci"
	InputTypeRemote ImageInputType = "remote"
)

type PackageType string

const (
	PkgTypeDeb  PackageType = "deb"
	PkgTypeRPM  PackageType = "rpm"
	PkgTypeAPK  PackageType = "apk"
	PkgTypePip  PackageType = "pip"
	PkgTypeNpm  PackageType = "npm"
	PkgTypeGo   PackageType = "go"
	PkgTypeMaven PackageType = "maven"
)

type ImageLayer struct {
	Index        int
	Digest       string
	AddedFiles   []string
	ModifiedFiles []string
	DeletedFiles []string
}

type Package struct {
	Name             string
	Version          string
	Type             PackageType
	LayerIdx         int
	FilePath         string
	Supplier         string
	Homepage         string
	License          string
	Depends          []string
	SHA256           string
	Architecture     string
	SourceInfo       string
	DependsOn        []string
}

type Vulnerability struct {
	ID           string
	Title        string
	CVE          string
	Severity     Severity
	PackageName  string
	PackageVersion string
	FixedVersion string
	Description  string
	LayerIdx     int
	CVSS         float64
}

type ComplianceIssue struct {
	RuleID      string
	RuleName    string
	Severity    Severity
	Description string
	Evidence    []string
}

type DockerfileIssue struct {
	RuleID      string
	RuleName    string
	Severity    Severity
	Description string
	Line        int
}

type ScanResult struct {
	ImageName       string
	Layers          []ImageLayer
	Packages        []Package
	Vulnerabilities []Vulnerability
	Compliance      []ComplianceIssue
	Dockerfile      []DockerfileIssue
	ScanTime        string
	TotalCritical   int
	TotalHigh       int
	TotalMedium     int
	TotalLow        int
}

type DiffResult struct {
	OldImage     string
	NewImage     string
	ScanTime     string
	VulnerabilityDiff VulnerabilityDiff
	PackageDiff   PackageDiff
	LayerDiff     LayerDiff
	ComplianceDiff ComplianceDiff
}

type VulnerabilityDiff struct {
	Added     []Vulnerability
	Removed   []Vulnerability
	Unchanged []Vulnerability
}

type PackageChange struct {
	Package     Package
	OldVersion  string
	NewVersion  string
	ChangeType  string
}

type PackageDiff struct {
	Added      []Package
	Removed    []Package
	Upgraded   []PackageChange
	Downgraded []PackageChange
	Unchanged  []Package
}

type LayerDiff struct {
	OldLayerCount int
	NewLayerCount int
	LayerChanges  []LayerChange
}

type LayerChange struct {
	Index         int
	OldFileCount  int
	NewFileCount  int
	AddedFiles    []string
	RemovedFiles  []string
	ModifiedFiles []string
	ChangeType    string
}

type ComplianceDiff struct {
	Added     []ComplianceIssue
	Removed   []ComplianceIssue
	Unchanged []ComplianceIssue
}

type Config struct {
	CacheDir       string
	CacheTTL       int
	OutputFormat   string
	OutputFile     string
	FailOn         Severity
	IgnoreFile     string
	DockerfilePath string
	RegistryAuth   RegistryAuth
}

type RegistryAuth struct {
	Username string
	Password string
	Token    string
}

type SensitivePattern struct {
	Name        string
	Patterns    []string
	Description string
}
