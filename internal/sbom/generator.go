package sbom

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"

	"imgscan/internal/config"
	"imgscan/internal/dependencies"
	"imgscan/internal/image"
	"imgscan/internal/osv"
	"imgscan/internal/packages"
	"imgscan/internal/utils"
)

var _ = sha256.Size

type Generator struct {
	imageRef       string
	inputType      string
	format         SBOMFormat
	outputFile     string
	dockerfilePath string
	baselinePath   string
	policyPath     string
	auth           config.RegistryAuth
	cacheDir       string
	cacheTTL       int
}

type GeneratorOption func(*Generator)

func WithFormat(f SBOMFormat) GeneratorOption {
	return func(g *Generator) { g.format = f }
}

func WithOutputFile(f string) GeneratorOption {
	return func(g *Generator) { g.outputFile = f }
}

func WithDockerfile(f string) GeneratorOption {
	return func(g *Generator) { g.dockerfilePath = f }
}

func WithBaseline(f string) GeneratorOption {
	return func(g *Generator) { g.baselinePath = f }
}

func WithPolicy(f string) GeneratorOption {
	return func(g *Generator) { g.policyPath = f }
}

func WithAuth(auth config.RegistryAuth) GeneratorOption {
	return func(g *Generator) { g.auth = auth }
}

func WithCache(dir string, ttl int) GeneratorOption {
	return func(g *Generator) { g.cacheDir = dir; g.cacheTTL = ttl }
}

func NewGenerator(imageRef, inputType string, opts ...GeneratorOption) *Generator {
	g := &Generator{
		imageRef:  imageRef,
		inputType: inputType,
		format:    FormatSPDXJSON,
		cacheTTL:  24,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

func (g *Generator) Generate() (*SBOMDocument, error) {
	auth := config.RegistryAuth{
		Username: utils.GetEnvWithDefault("REGISTRY_USER", g.auth.Username),
		Password: utils.GetEnvWithDefault("REGISTRY_PASS", g.auth.Password),
		Token:    utils.GetEnvWithDefault("REGISTRY_TOKEN", g.auth.Token),
	}

	actualInputType := g.inputType
	if actualInputType == "auto" {
		actualInputType = string(detectSBOMInputType(g.imageRef))
	}
	if actualInputType == "" {
		return nil, fmt.Errorf("could not detect input type for %s", g.imageRef)
	}

	parser := image.NewImageParser()
	fmt.Fprintf(os.Stderr, "Parsing image: %s (type: %s)\n", g.imageRef, actualInputType)

	scanResult, err := parser.Parse(g.imageRef, config.ImageInputType(actualInputType), auth)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image: %w", err)
	}

	scanResult.ScanTime = utils.NowISO()

	fileMap := make(map[string]int)
	for _, layer := range scanResult.Layers {
		for _, f := range layer.AddedFiles {
			fileMap[f] = layer.Index
		}
		for _, f := range layer.ModifiedFiles {
			fileMap[f] = layer.Index
		}
	}

	fileContentMap := make(map[string][]byte)
	for path := range fileMap {
		if content, err := parser.GetFileContent(path); err == nil {
			fileContentMap[path] = content
		}
	}

	osScanner := packages.NewScanner(fileMap)
	osPackages := osScanner.ScanOSPackages(fileContentMap)
	scanResult.Packages = append(scanResult.Packages, osPackages...)

	depScanner := dependencies.NewScanner(fileMap)
	depPackages := depScanner.ScanDependencies(fileContentMap)
	scanResult.Packages = append(scanResult.Packages, depPackages...)

	fmt.Fprintf(os.Stderr, "Found %d OS packages, %d application dependencies\n", len(osPackages), len(depPackages))

	licenseScanner := NewLicenseScanner()
	licenseFiles := parser.FindLicenseFiles()
	pkgLicenses := ScanLicensesForPackages(licenseFiles, licenseScanner)

	provenanceBuilder := NewProvenanceBuilder(scanResult.Packages, fileMap)
	provenanceMap := provenanceBuilder.BuildAll()

	sbomPackages := make([]SBOMPackage, 0, len(scanResult.Packages))
	for _, pkg := range scanResult.Packages {
		sbomPkg := g.convertPackage(pkg, pkgLicenses, provenanceMap)
		sbomPackages = append(sbomPackages, sbomPkg)
	}

	var vulnerabilities []config.Vulnerability
	osvClient, err := osv.NewClient(g.cacheDir, g.cacheTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to create OSV client: %v\n", err)
	} else {
		defer osvClient.Close()
		fmt.Fprintln(os.Stderr, "Querying OSV for vulnerabilities...")
		vulnerabilities = osvClient.QueryBatch(scanResult.Packages)
	}

	sbomPackages = MapVulnerabilitiesToPackages(vulnerabilities, sbomPackages)

	riskScorer := NewRiskScorer(vulnerabilities, sbomPackages)
	riskScores := riskScorer.ScoreAll()
	totalRisk := riskScorer.CalculateTotalRisk(riskScores)

	for i := range sbomPackages {
		if score, ok := riskScores[sbomPackages[i].ID]; ok {
			sbomPackages[i].RiskScore = score
		}
	}

	sigChecker := NewSignatureChecker(g.imageRef, auth)
	sigResult := sigChecker.Check()

	var reproResult ReproducibilityResult
	if g.dockerfilePath != "" {
		reproChecker := NewReproducibilityChecker(g.dockerfilePath, sbomPackages, scanResult)
		reproResult = reproChecker.Check()
	}

	namespace := fmt.Sprintf("https://imgscan.sbom/%s-%s", sanitizeID(g.imageRef), time.Now().Format("20060102150405"))

	doc := &SBOMDocument{
		Name:            fmt.Sprintf("SBOM for %s", g.imageRef),
		Namespace:       namespace,
		Created:         time.Now().UTC().Format(time.RFC3339),
		Creators:        []Creator{{Name: "imgscan", Type: "Tool"}},
		Packages:        sbomPackages,
		Relationships:   buildRelationships(sbomPackages, provenanceBuilder),
		Vulnerabilities: convertVulns(vulnerabilities, sbomPackages),
		Signature:       sigResult,
		Reproducibility: reproResult,
		ImageName:       g.imageRef,
		TotalRiskScore:  totalRisk,
	}

	if g.baselinePath != "" {
		baseline, err := g.loadBaseline()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load baseline: %v\n", err)
		} else if baseline != nil {
			comparator := NewIncrementalComparator(doc, baseline)
			incResult := comparator.Compare()
			incJSON, _ := RenderIncrementalResult(incResult)
			fmt.Fprintf(os.Stderr, "Incremental SBOM changes:\n%s\n", string(incJSON))
		}
	}

	if g.policyPath != "" {
		policyEngine, err := NewPolicyEngine(g.policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load policy: %v\n", err)
		} else {
			policyResult := policyEngine.Evaluate(doc)
			doc.PolicyResult = policyResult
			fmt.Fprintln(os.Stderr, FormatPolicyResult(policyResult))
		}
	}

	return doc, nil
}

func (g *Generator) convertPackage(pkg config.Package, pkgLicenses map[string]string, provenanceMap map[string]ProvenanceInfo) SBOMPackage {
	id := PkgID(pkg.Name, pkg.Version, pkg.Type)

	licenseConcluded := "NOASSERTION"
	licenseDeclared := "NOASSERTION"

	if pkg.License != "" {
		match := NewLicenseScanner().IdentifyLicenseString(pkg.License)
		licenseConcluded = match.SPDXID
		licenseDeclared = match.SPDXID
	}

	dirLicense := FindLicenseForPackage(pkg.FilePath, pkgLicenses)
	if licenseConcluded == "NOASSERTION" && dirLicense != "" {
		licenseConcluded = dirLicense
	}

	provenance := ProvenanceInfo{
		LayerIndex:    pkg.LayerIdx,
		InstallMethod: detectMethod(pkg.Type),
		IsDirect:      true,
	}
	if prov, ok := provenanceMap[id]; ok {
		provenance = prov
	}

	downloadLocation := pkg.Homepage
	if downloadLocation == "" {
		downloadLocation = "NOASSERTION"
	}

	pkgSHA256 := pkg.SHA256
	if pkgSHA256 == "" {
		h := sha256.Sum256([]byte(id))
		pkgSHA256 = fmt.Sprintf("%x", h)
	}

	return SBOMPackage{
		ID:               id,
		Name:             pkg.Name,
		Version:          pkg.Version,
		Supplier:         pkg.Supplier,
		LicenseConcluded: licenseConcluded,
		LicenseDeclared:  licenseDeclared,
		DownloadLocation: downloadLocation,
		SHA256:           pkgSHA256,
		PackageType:      pkg.Type,
		PackageFile:      pkg.FilePath,
		Provenance:       provenance,
		Architecture:     pkg.Architecture,
		SourceInfo:       pkg.SourceInfo,
	}
}

func (g *Generator) loadBaseline() (*SBOMDocument, error) {
	data, err := os.ReadFile(g.baselinePath)
	if err != nil {
		return nil, err
	}
	return LoadBaseline(data)
}

func buildRelationships(packages []SBOMPackage, pb *ProvenanceBuilder) []SBOMRelationship {
	var rels []SBOMRelationship

	pkgMap := make(map[string]string)
	for _, pkg := range packages {
		pkgMap[strings.ToLower(pkg.Name)] = pkg.ID
	}

	for _, pkg := range packages {
		if pkg.Provenance.IsDirect {
			rels = append(rels, SBOMRelationship{
				SourceID:        "DOCUMENT",
				RelationshipType: "DESCRIBES",
				TargetID:        pkg.ID,
			})
		}

		for _, depName := range pkg.Provenance.DependencyPath {
			if depID, ok := pkgMap[strings.ToLower(depName)]; ok && depID != pkg.ID {
				rels = append(rels, SBOMRelationship{
					SourceID:        pkg.ID,
					RelationshipType: "DEPENDS_ON",
					TargetID:        depID,
				})
			}
		}
	}

	return rels
}

func convertVulns(vulns []config.Vulnerability, packages []SBOMPackage) []SBOMVulnerability {
	var result []SBOMVulnerability
	for _, v := range vulns {
		url := ""
		if v.CVE != "" {
			url = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CVE)
		}
		result = append(result, SBOMVulnerability{
			CVE:          v.CVE,
			ID:           v.ID,
			Severity:     v.Severity,
			URL:          url,
			FixedVersion: v.FixedVersion,
			Description:  v.Description,
			CVSS:         v.CVSS,
		})
	}
	return result
}

func detectMethod(pkgType config.PackageType) string {
	switch pkgType {
	case config.PkgTypeDeb:
		return "apt/dpkg"
	case config.PkgTypeRPM:
		return "yum/rpm"
	case config.PkgTypeAPK:
		return "apk"
	case config.PkgTypePip:
		return "pip"
	case config.PkgTypeNpm:
		return "npm"
	case config.PkgTypeGo:
		return "go-modules"
	case config.PkgTypeMaven:
		return "maven"
	default:
		return "unknown"
	}
}

func detectSBOMInputType(imageRef string) config.ImageInputType {
	if info, err := os.Stat(imageRef); err == nil {
		if info.IsDir() {
			if _, err := os.Stat(imageRef + "/index.json"); err == nil {
				return config.InputTypeOCI
			}
		} else {
			if strings.HasSuffix(strings.ToLower(imageRef), ".tar") ||
				strings.HasSuffix(strings.ToLower(imageRef), ".tar.gz") {
				return config.InputTypeTar
			}
		}
	}
	return config.InputTypeRemote
}

func (g *Generator) Render(doc *SBOMDocument) ([]byte, error) {
	switch g.format {
	case FormatSPDXJSON:
		return RenderSPDXJSON(doc)
	case FormatSPDXTV:
		return RenderSPDXTV(doc)
	case FormatCycloneDXJSON:
		return RenderCycloneDXJSON(doc)
	case FormatCycloneDXXML:
		return RenderCycloneDXXML(doc)
	default:
		return RenderSPDXJSON(doc)
	}
}

func (g *Generator) WriteOutput(data []byte) error {
	if g.outputFile != "" {
		return os.WriteFile(g.outputFile, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func (g *Generator) GetExitCode(doc *SBOMDocument) int {
	if HasPolicyViolations(doc.PolicyResult) {
		return 3
	}
	return 0
}
