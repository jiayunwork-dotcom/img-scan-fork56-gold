package sbom

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"imgscan/internal/config"
)

type ReproducibilityChecker struct {
	dockerfilePath string
	packages       []SBOMPackage
	scanResult     *config.ScanResult
}

func NewReproducibilityChecker(dockerfilePath string, packages []SBOMPackage, scanResult *config.ScanResult) *ReproducibilityChecker {
	return &ReproducibilityChecker{
		dockerfilePath: dockerfilePath,
		packages:       packages,
		scanResult:     scanResult,
	}
}

func (rc *ReproducibilityChecker) Check() ReproducibilityResult {
	result := ReproducibilityResult{}

	if rc.dockerfilePath == "" {
		return result
	}

	dockerfilePkgs, baseImagePkgs, err := rc.parseDockerfilePackages()
	if err != nil {
		result.ConsistencyScore = -1
		return result
	}

	actualPkgMap := make(map[string]SBOMPackage)
	for _, pkg := range rc.packages {
		key := strings.ToLower(pkg.Name)
		actualPkgMap[key] = pkg
	}

	declaredSet := make(map[string]bool)
	for _, name := range dockerfilePkgs {
		declaredSet[strings.ToLower(name)] = true
	}
	for _, name := range baseImagePkgs {
		declaredSet[strings.ToLower(name)] = true
	}

	for _, pkg := range rc.packages {
		lowerName := strings.ToLower(pkg.Name)
		if !declaredSet[lowerName] {
			reason := "unknown-source"
			if pkg.Provenance.LayerIndex == 0 {
				reason = "base-image-builtin"
			} else if pkg.Provenance.InstallMethod != "" {
				reason = "transitive-dependency"
			}
			result.GhostPackages = append(result.GhostPackages, DiscrepancyItem{
				Name:       pkg.Name,
				Version:    pkg.Version,
				Reason:     reason,
				PackageRef: pkg.ID,
			})
		}
	}

	for _, name := range dockerfilePkgs {
		lowerName := strings.ToLower(name)
		if _, exists := actualPkgMap[lowerName]; !exists {
			reason := "install-failed-or-removed"
			if isBaseImagePackage(name) {
				reason = "base-image-not-present"
			}
			result.MissingPackages = append(result.MissingPackages, DiscrepancyItem{
				Name:   name,
				Reason: reason,
			})
		}
	}

	totalDeclared := len(declaredSet)
	if totalDeclared == 0 {
		totalDeclared = 1
	}
	matchedCount := totalDeclared - len(result.MissingPackages)
	result.ConsistencyScore = float64(matchedCount) / float64(totalDeclared) * 100

	return result
}

func (rc *ReproducibilityChecker) parseDockerfilePackages() ([]string, []string, error) {
	content, err := os.ReadFile(rc.dockerfilePath)
	if err != nil {
		return nil, nil, err
	}

	var installPkgs []string
	var baseImagePkgs []string
	isMultiStage := false
	stageIdx := 0
	lastStageIdx := 0

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "FROM") {
			stageIdx++
			isMultiStage = true
			lastStageIdx = stageIdx
		}
	}

	currentStage := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "FROM") {
			currentStage++
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				baseImage := parts[1]
				if currentStage == lastStageIdx || !isMultiStage {
					baseImagePkgs = append(baseImagePkgs, "base:"+baseImage)
				}
			}
			continue
		}

		if isMultiStage && currentStage < lastStageIdx {
			continue
		}

		if strings.HasPrefix(trimmed, "RUN") {
			pkgs := extractPackagesFromRUN(trimmed)
			installPkgs = append(installPkgs, pkgs...)
		}

		if strings.HasPrefix(trimmed, "COPY") && strings.Contains(trimmed, "--from=") {
		}
	}

	return installPkgs, baseImagePkgs, nil
}

func extractPackagesFromRUN(runLine string) []string {
	var packages []string

	cmd := strings.TrimPrefix(runLine, "RUN")
	cmd = strings.TrimSpace(cmd)

	cmd = strings.ReplaceAll(cmd, "&&", ";")
	cmd = strings.ReplaceAll(cmd, "||", ";")
	cmd = strings.ReplaceAll(cmd, "\\\n", " ")

	segments := strings.Split(cmd, ";")
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		pkgs := parseInstallCommand(seg)
		packages = append(packages, pkgs...)
	}

	return packages
}

func parseInstallCommand(cmd string) []string {
	var packages []string

	scanner := bufio.NewScanner(strings.NewReader(cmd))
	scanner.Split(bufio.ScanWords)

	inInstall := false
	packageMgr := ""

	for scanner.Scan() {
		word := scanner.Text()

		if isInstallCommand(word) {
			inInstall = true
			packageMgr = word
			continue
		}

		if inInstall {
			if strings.HasPrefix(word, "-") {
				if word == "--" {
					continue
				}
				continue
			}

			if isCommandSeparator(word) || isSubCommand(word) {
				inInstall = false
				continue
			}

			pkgName := cleanPackageName(word, packageMgr)
			if pkgName != "" {
				packages = append(packages, pkgName)
			}
		}
	}

	return packages
}

func isInstallCommand(word string) bool {
	installCmds := []string{
		"install", "add", "pip install", "npm install",
		"gem install", "go install", "cargo install",
		"apt-get install", "apt install", "yum install",
		"dnf install", "apk add", "pip3 install",
	}
	for _, cmd := range installCmds {
		if word == cmd {
			return true
		}
	}
	return false
}

func isCommandSeparator(word string) bool {
	separators := []string{"&&", "||", ";", "|", ">", ">>"}
	for _, sep := range separators {
		if word == sep {
			return true
		}
	}
	return false
}

func isSubCommand(word string) bool {
	subCmds := []string{"&&", "rm", "cd", "mkdir", "cp", "mv", "ln", "chmod", "chown",
		"echo", "export", "env", "set", "unset", "sed", "awk", "grep", "find",
		"curl", "wget", "tar", "unzip", "apt-get", "apt", "yum", "dnf", "apk",
		"update", "upgrade", "clean", "autoremove"}
	for _, cmd := range subCmds {
		if word == cmd {
			return true
		}
	}
	return false
}

func cleanPackageName(name, packageMgr string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ",")

	if strings.HasPrefix(name, "${") || strings.HasPrefix(name, "$") {
		return ""
	}

	switch packageMgr {
	case "pip", "pip3", "pip install", "pip3 install":
		if strings.HasPrefix(name, "-r") || strings.HasPrefix(name, "-e") {
			return ""
		}
		if idx := strings.IndexAny(name, "=<>!~"); idx != -1 {
			name = name[:idx]
		}
	case "npm", "npm install":
		if strings.HasPrefix(name, "-") {
			return ""
		}
		if strings.HasPrefix(name, "@") {
			return name
		}
		if idx := strings.IndexAny(name, "@"); idx > 0 {
			name = name[:idx]
		}
	case "go", "go install":
		if idx := strings.LastIndex(name, "@"); idx != -1 {
			name = name[:idx]
		}
		if strings.Contains(name, "/") {
			parts := strings.Split(name, "/")
			name = parts[len(parts)-1]
		}
	default:
		if idx := strings.IndexAny(name, "=<>"); idx != -1 {
			name = name[:idx]
		}
	}

	return name
}

func isBaseImagePackage(name string) bool {
	return strings.HasPrefix(name, "base:")
}

func FormatReproducibility(result ReproducibilityResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Consistency Score: %.1f%%\n", result.ConsistencyScore))

	if len(result.GhostPackages) > 0 {
		sb.WriteString("\nGhost Dependencies (present in image but not declared in Dockerfile):\n")
		for _, gp := range result.GhostPackages {
			sb.WriteString(fmt.Sprintf("  - %s %s (%s)\n", gp.Name, gp.Version, gp.Reason))
		}
	}

	if len(result.MissingPackages) > 0 {
		sb.WriteString("\nMissing Dependencies (declared in Dockerfile but not found in image):\n")
		for _, mp := range result.MissingPackages {
			sb.WriteString(fmt.Sprintf("  - %s (%s)\n", mp.Name, mp.Reason))
		}
	}

	return sb.String()
}
