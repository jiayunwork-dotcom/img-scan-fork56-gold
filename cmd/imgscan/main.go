package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"imgscan/internal/compliance"
	"imgscan/internal/config"
	"imgscan/internal/dependencies"
	"imgscan/internal/sbom"
	"imgscan/internal/diff"
	"imgscan/internal/dockerfile"
	"imgscan/internal/image"
	"imgscan/internal/osv"
	"imgscan/internal/packages"
	"imgscan/internal/report"
	"imgscan/internal/utils"
)

var (
	inputType      string
	outputFormat   string
	outputFile     string
	cacheDir       string
	cacheTTL       int
	failOn         string
	ignoreFile     string
	dockerfilePath string
	registryUser   string
	registryPass   string
	registryToken  string

	diffOldInputType string
	diffNewInputType string

	sbomFormat    string
	sbomBaseline  string
	sbomPolicy    string
	sbomInteractive bool
	sbomSignKey    string

	watchDir      string
	watchPolicy   string
	watchWebhook  string
	watchAuditLog string
	watchPubKey   string

	verifyPubKey string
)

var rootCmd = &cobra.Command{
	Use:   "imgscan [image]",
	Short: "Container image security scanner",
	Long:  `Scan container images for vulnerabilities, compliance issues, and Dockerfile best practices.`,
	Args:  cobra.ExactArgs(1),
	Run:   runScan,
}

var diffCmd = &cobra.Command{
	Use:   "diff [old-image] [new-image]",
	Short: "Compare security status between two images",
	Long:  `Compare vulnerabilities, package versions, layer structure, and compliance between two container images.`,
	Args:  cobra.ExactArgs(2),
	Run:   runDiff,
}

var sbomCmd = &cobra.Command{
	Use:   "sbom <image>",
	Short: "Generate SBOM for container image",
	Long:  `Generate Software Bill of Materials (SBOM) with supply chain tracing, license identification, and vulnerability correlation.`,
	Args:  cobra.ExactArgs(1),
	Run:   runSBOM,
}

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch directory for SBOM file changes and evaluate policies",
	Long:  `Monitor a directory for new or updated SBOM files, automatically evaluate them against a policy, and report violations.`,
	Run:   runWatch,
}

var verifyCmd = &cobra.Command{
	Use:   "verify <sbom-file>",
	Short: "Verify SBOM file Ed25519 signature",
	Long:  `Verify the Ed25519 signature of an SBOM file using the provided public key.`,
	Args:  cobra.ExactArgs(1),
	Run:   runVerify,
}

func init() {
	rootCmd.Flags().StringVarP(&inputType, "input", "i", "auto", "Input type: auto, tar, oci, remote")
	rootCmd.Flags().StringVarP(&outputFormat, "format", "f", "console", "Output format: console, json, sarif, html")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	rootCmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Cache directory for OSV data")
	rootCmd.Flags().IntVar(&cacheTTL, "cache-ttl", 24, "Cache TTL in hours")
	rootCmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail on severity level: none, low, medium, high, critical")
	rootCmd.Flags().StringVar(&ignoreFile, "ignore", ".scanignore", "Ignore list file")
	rootCmd.Flags().StringVar(&dockerfilePath, "dockerfile", "", "Path to Dockerfile for best practices check")
	rootCmd.Flags().StringVar(&registryUser, "registry-user", "", "Registry username")
	rootCmd.Flags().StringVar(&registryPass, "registry-pass", "", "Registry password")
	rootCmd.Flags().StringVar(&registryToken, "registry-token", "", "Registry token")

	diffCmd.Flags().StringVar(&diffOldInputType, "old-input-type", "auto", "Input type for old image: auto, tar, oci, remote")
	diffCmd.Flags().StringVar(&diffNewInputType, "new-input-type", "auto", "Input type for new image: auto, tar, oci, remote")
	diffCmd.Flags().StringVarP(&outputFormat, "format", "f", "console", "Output format: console, json, html")
	diffCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	diffCmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Cache directory for OSV data")
	diffCmd.Flags().IntVar(&cacheTTL, "cache-ttl", 24, "Cache TTL in hours")
	diffCmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail on severity level: none, low, medium, high, critical")
	diffCmd.Flags().StringVar(&ignoreFile, "ignore", ".scanignore", "Ignore list file")
	diffCmd.Flags().StringVar(&registryUser, "registry-user", "", "Registry username")
	diffCmd.Flags().StringVar(&registryPass, "registry-pass", "", "Registry password")
	diffCmd.Flags().StringVar(&registryToken, "registry-token", "", "Registry token")

	sbomCmd.Flags().StringVarP(&inputType, "input", "i", "auto", "Input type: auto, tar, oci, remote")
	sbomCmd.Flags().StringVar(&sbomFormat, "sbom-format", "spdx-json", "SBOM format: spdx-json, spdx-tv, cyclonedx-json, cyclonedx-xml")
	sbomCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	sbomCmd.Flags().StringVar(&dockerfilePath, "dockerfile", "", "Path to Dockerfile for reproducibility check")
	sbomCmd.Flags().StringVar(&sbomBaseline, "baseline", "", "Path to baseline SBOM file for incremental comparison")
	sbomCmd.Flags().StringVar(&sbomPolicy, "policy", "", "Path to policy YAML file")
	sbomCmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Cache directory for OSV data")
	sbomCmd.Flags().IntVar(&cacheTTL, "cache-ttl", 24, "Cache TTL in hours")
	sbomCmd.Flags().StringVar(&registryUser, "registry-user", "", "Registry username")
	sbomCmd.Flags().StringVar(&registryPass, "registry-pass", "", "Registry password")
	sbomCmd.Flags().StringVar(&registryToken, "registry-token", "", "Registry token")
	sbomCmd.Flags().BoolVar(&sbomInteractive, "interactive", false, "Launch interactive dependency tree explorer")
	sbomCmd.Flags().StringVar(&sbomSignKey, "sign", "", "Sign SBOM with Ed25519 private key")

	watchCmd.Flags().StringVar(&watchDir, "dir", ".", "Directory to watch for SBOM files")
	watchCmd.Flags().StringVar(&watchPolicy, "policy", "", "Path to policy YAML file (required)")
	watchCmd.Flags().StringVar(&watchWebhook, "webhook", "", "Webhook URL for violation notifications")
	watchCmd.Flags().StringVar(&watchAuditLog, "audit-log", "./sbom-audit.log", "Path to audit log file")
	watchCmd.Flags().StringVar(&watchPubKey, "pubkey", "", "Path to public key for SBOM signature verification")

	verifyCmd.Flags().StringVar(&verifyPubKey, "pubkey", "", "Path to Ed25519 public key (required)")
	verifyCmd.MarkFlagRequired("pubkey")

	sbomCmd.AddCommand(watchCmd)

	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(sbomCmd)
	rootCmd.AddCommand(verifyCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	imageRef := args[0]
	result := scanImage(imageRef, inputType)

	reporter := report.NewReporter(outputFormat, outputFile)
	if err := reporter.Generate(result); err != nil {
		fmt.Printf("Error generating report: %v\n", err)
		os.Exit(1)
	}

	exitCode := config.GetExitCode(result, config.Severity(strings.ToUpper(failOn[:1])+failOn[1:]), loadIgnoreList())
	os.Exit(exitCode)
}

func runDiff(cmd *cobra.Command, args []string) {
	oldImageRef := args[0]
	newImageRef := args[1]

	fmt.Printf("Scanning old image: %s\n", oldImageRef)
	oldResult := scanImage(oldImageRef, diffOldInputType)

	fmt.Printf("Scanning new image: %s\n", newImageRef)
	newResult := scanImage(newImageRef, diffNewInputType)

	diffResult := diff.Compare(oldResult, newResult)

	reporter := report.NewDiffReporter(outputFormat, outputFile)
	if err := reporter.Generate(diffResult); err != nil {
		fmt.Printf("Error generating diff report: %v\n", err)
		os.Exit(1)
	}

	exitCode := getDiffExitCode(diffResult, config.Severity(strings.ToUpper(failOn[:1])+failOn[1:]))
	os.Exit(exitCode)
}

func runSBOM(cmd *cobra.Command, args []string) {
	imageRef := args[0]

	auth := config.RegistryAuth{
		Username: registryUser,
		Password: registryPass,
		Token:    registryToken,
	}

	gen := sbom.NewGenerator(
		imageRef,
		inputType,
		sbom.WithFormat(sbom.SBOMFormat(sbomFormat)),
		sbom.WithOutputFile(outputFile),
		sbom.WithDockerfile(dockerfilePath),
		sbom.WithBaseline(sbomBaseline),
		sbom.WithPolicy(sbomPolicy),
		sbom.WithAuth(auth),
		sbom.WithCache(cacheDir, cacheTTL),
	)

	doc, err := gen.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating SBOM: %v\n", err)
		os.Exit(1)
	}

	if sbomSignKey != "" {
		sigB64, err := sbom.SignSBOM(doc, sbomSignKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error signing SBOM: %v\n", err)
			os.Exit(1)
		}
		doc.Ed25519Signature = sigB64
		fmt.Fprintf(os.Stderr, "SBOM signed with Ed25519\n")
	}

	data, err := gen.Render(doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error rendering SBOM: %v\n", err)
		os.Exit(1)
	}

	if sbomSignKey != "" && outputFile != "" {
		data, err = sbom.SignSBOMData(data, sbomSignKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error signing SBOM data: %v\n", err)
			os.Exit(1)
		}
	}

	if err := gen.WriteOutput(data); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing SBOM output: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n--- SBOM Summary ---\n")
	fmt.Fprintf(os.Stderr, "Image: %s\n", doc.ImageName)
	fmt.Fprintf(os.Stderr, "Packages: %d\n", len(doc.Packages))
	fmt.Fprintf(os.Stderr, "Total Risk Score: %.1f/100\n", doc.TotalRiskScore)
	if doc.Ed25519Signature != "" {
		fmt.Fprintf(os.Stderr, "Ed25519 Signature: %s...%s\n", doc.Ed25519Signature[:20], doc.Ed25519Signature[len(doc.Ed25519Signature)-8:])
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", sbom.FormatSignature(doc.Signature))

	if doc.Reproducibility.ConsistencyScore > 0 {
		fmt.Fprintf(os.Stderr, "\n%s\n", sbom.FormatReproducibility(doc.Reproducibility))
	}

	if sbomInteractive {
		fmt.Fprintf(os.Stderr, "\nLaunching interactive dependency tree explorer...\n")
		if err := sbom.RunInteractive(doc); err != nil {
			fmt.Fprintf(os.Stderr, "Interactive mode error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	exitCode := gen.GetExitCode(doc)
	os.Exit(exitCode)
}

func runWatch(cmd *cobra.Command, args []string) {
	if watchPolicy == "" {
		fmt.Fprintf(os.Stderr, "Error: --policy flag is required for watch mode\n")
		os.Exit(1)
	}

	dir, err := filepath.Abs(watchDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving directory path: %v\n", err)
		os.Exit(1)
	}

	watcher := sbom.NewWatcher(dir, watchPolicy, watchWebhook, watchAuditLog, watchPubKey)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		watcher.Stop()
	}()

	if err := watcher.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting watcher: %v\n", err)
		os.Exit(1)
	}

	select {}
}

func runVerify(cmd *cobra.Command, args []string) {
	sbomPath := args[0]

	if _, err := os.Stat(sbomPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: SBOM file not found: %s\n", sbomPath)
		os.Exit(1)
	}

	err := sbom.VerifySBOMFile(sbomPath, verifyPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Signature verification FAILED: %v\n", err)

		data, readErr := os.ReadFile(sbomPath)
		if readErr == nil {
			var rawMap map[string]json.RawMessage
			if json.Unmarshal(data, &rawMap) == nil {
				if _, ok := rawMap["_ed25519_signature"]; !ok {
					fmt.Fprintf(os.Stderr, "  Reason: SBOM file does not contain an Ed25519 signature\n")
				}
			}
		}
		os.Exit(4)
	}

	fmt.Fprintf(os.Stderr, "✓ Signature verification PASSED: %s\n", sbomPath)
	os.Exit(0)
}

func scanImage(imageRef, inputTypeFlag string) *config.ScanResult {
	actualInputType := detectInputType(imageRef, inputTypeFlag)
	if actualInputType == "" {
		fmt.Printf("Error: Could not detect input type for %s\n", imageRef)
		os.Exit(1)
	}

	auth := config.RegistryAuth{
		Username: utils.GetEnvWithDefault("REGISTRY_USER", registryUser),
		Password: utils.GetEnvWithDefault("REGISTRY_PASS", registryPass),
		Token:    utils.GetEnvWithDefault("REGISTRY_TOKEN", registryToken),
	}

	parser := image.NewImageParser()
	fmt.Printf("Parsing image: %s (type: %s)\n", imageRef, actualInputType)

	result, err := parser.Parse(imageRef, actualInputType, auth)
	if err != nil {
		fmt.Printf("Error parsing image: %v\n", err)
		os.Exit(1)
	}

	result.ScanTime = utils.NowISO()

	fileMap := make(map[string]int)
	for _, layer := range result.Layers {
		for _, f := range layer.AddedFiles {
			fileMap[f] = layer.Index
		}
		for _, f := range layer.ModifiedFiles {
			fileMap[f] = layer.Index
		}
	}

	fileContentMap := make(map[string][]byte)
	for path := range fileMap {
		if isRelevantFile(path) {
			if content, err := parser.GetFileContent(path); err == nil {
				fileContentMap[path] = content
			}
		}
	}

	osScanner := packages.NewScanner(fileMap)
	osPackages := osScanner.ScanOSPackages(fileContentMap)
	result.Packages = append(result.Packages, osPackages...)

	depScanner := dependencies.NewScanner(fileMap)
	depPackages := depScanner.ScanDependencies(fileContentMap)
	result.Packages = append(result.Packages, depPackages...)

	fmt.Printf("Found %d OS packages, %d application dependencies\n", len(osPackages), len(depPackages))

	osvClient, err := osv.NewClient(cacheDir, cacheTTL)
	if err != nil {
		fmt.Printf("Warning: Failed to create OSV client: %v\n", err)
	} else {
		defer osvClient.Close()
		fmt.Println("Querying OSV for vulnerabilities...")
		vulns := osvClient.QueryBatch(result.Packages)
		result.Vulnerabilities = vulns
	}

	for _, v := range result.Vulnerabilities {
		switch v.Severity {
		case config.SeverityCritical:
			result.TotalCritical++
		case config.SeverityHigh:
			result.TotalHigh++
		case config.SeverityMedium:
			result.TotalMedium++
		case config.SeverityLow:
			result.TotalLow++
		}
	}

	history := make([]string, len(result.Layers))
	for i, layer := range result.Layers {
		history[i] = layer.Digest
	}
	imageUser := ""
	complianceScanner := compliance.NewScanner(fileMap, result.Packages, imageUser, history)
	result.Compliance = complianceScanner.Scan()

	if dockerfilePath != "" {
		dfChecker := dockerfile.NewChecker(dockerfilePath)
		if issues, err := dfChecker.Check(); err == nil {
			result.Dockerfile = issues
		}
	}

	ignore := loadIgnoreList()
	result.Vulnerabilities = ignore.FilterVulnerabilities(result.Vulnerabilities)

	return result
}

func loadIgnoreList() *config.IgnoreList {
	ignore, err := config.LoadIgnoreList(ignoreFile)
	if err != nil {
		fmt.Printf("Warning: Failed to load ignore list: %v\n", err)
	}
	return ignore
}

func getDiffExitCode(diffResult *config.DiffResult, failOn config.Severity) int {
	severityOrder := map[config.Severity]int{
		config.SeverityCritical: 4,
		config.SeverityHigh:     3,
		config.SeverityMedium:   2,
		config.SeverityLow:      1,
		config.SeverityNone:     0,
	}

	targetLevel := severityOrder[failOn]
	highestAdded := diff.GetHighestAddedSeverity(diffResult)

	if severityOrder[highestAdded] >= targetLevel {
		switch highestAdded {
		case config.SeverityCritical:
			return 2
		default:
			return 1
		}
	}

	totalAdded := len(diffResult.VulnerabilityDiff.Added)
	totalRemoved := len(diffResult.VulnerabilityDiff.Removed)
	if totalRemoved > 0 && totalAdded == 0 {
		return 0
	}

	return 0
}

func detectInputType(imageRef, inputType string) config.ImageInputType {
	if inputType != "auto" {
		return config.ImageInputType(inputType)
	}

	if info, err := os.Stat(imageRef); err == nil {
		if info.IsDir() {
			if _, err := os.Stat(filepath.Join(imageRef, "index.json")); err == nil {
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

func isRelevantFile(path string) bool {
	relevantSuffixes := []string{
		"var/lib/dpkg/status",
		"lib/apk/db/installed",
		"requirements.txt",
		"Pipfile.lock",
		"package-lock.json",
		"yarn.lock",
		"go.sum",
		"pom.xml",
		"gradle.lockfile",
	}

	for _, suffix := range relevantSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
