package dependencies

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"imgscan/internal/config"
)

type DependencyScanner struct {
	fileLayerMap map[string]int
}

func NewScanner(fileLayerMap map[string]int) *DependencyScanner {
	return &DependencyScanner{
		fileLayerMap: fileLayerMap,
	}
}

func (s *DependencyScanner) ScanDependencies(fileContentMap map[string][]byte) []config.Package {
	var packages []config.Package

	for path, content := range fileContentMap {
		layerIdx := s.fileLayerMap[path]

		switch {
		case strings.HasSuffix(path, "requirements.txt"):
			if pkgs, err := parseRequirementsTXT(content, layerIdx, path); err == nil {
				packages = append(packages, pkgs...)
			}
		case strings.HasSuffix(path, "Pipfile.lock"):
			if pkgs, err := parsePipfileLock(content, layerIdx, path); err == nil {
				packages = append(packages, pkgs...)
			}
		case strings.HasSuffix(path, "package-lock.json"):
			if pkgs, err := parsePackageLockJSON(content, layerIdx, path); err == nil {
				packages = append(packages, pkgs...)
			}
		case strings.HasSuffix(path, "yarn.lock"):
			if pkgs, err := parseYarnLock(content, layerIdx, path); err == nil {
				packages = append(packages, pkgs...)
			}
		case strings.HasSuffix(path, "go.sum"):
			if pkgs, err := parseGoSum(content, layerIdx, path); err == nil {
				packages = append(packages, pkgs...)
			}
		case strings.HasSuffix(path, "pom.xml"):
			if pkgs, err := parsePomXML(content, layerIdx, path); err == nil {
				packages = append(packages, pkgs...)
			}
		case strings.HasSuffix(path, "gradle.lockfile"):
			if pkgs, err := parseGradleLockfile(content, layerIdx, path); err == nil {
				packages = append(packages, pkgs...)
			}
		}
	}

	return packages
}

func parseRequirementsTXT(content []byte, layerIdx int, path string) ([]config.Package, error) {
	var packages []config.Package

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-r") {
			continue
		}

		name, version := parseRequirementLine(line)
		if name != "" {
			packages = append(packages, config.Package{
				Name:     name,
				Version:  version,
				Type:     config.PkgTypePip,
				LayerIdx: layerIdx,
				FilePath: path,
			})
		}
	}

	return packages, scanner.Err()
}

func parseRequirementLine(line string) (string, string) {
	ops := []string{">=", "<=", "==", "!=", ">", "<", "~="}
	for _, op := range ops {
		if idx := strings.Index(line, op); idx != -1 {
			name := strings.TrimSpace(line[:idx])
			version := strings.TrimSpace(line[idx+len(op):])
			if idx := strings.Index(version, ";"); idx != -1 {
				version = strings.TrimSpace(version[:idx])
			}
			return name, version
		}
	}
	return strings.TrimSpace(line), ""
}

func parsePipfileLock(content []byte, layerIdx int, path string) ([]config.Package, error) {
	var data struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}

	if err := json.Unmarshal(content, &data); err != nil {
		return nil, err
	}

	var packages []config.Package

	for name, info := range data.Default {
		packages = append(packages, config.Package{
			Name:     name,
			Version:  strings.TrimPrefix(info.Version, "=="),
			Type:     config.PkgTypePip,
			LayerIdx: layerIdx,
			FilePath: path,
		})
	}

	for name, info := range data.Develop {
		packages = append(packages, config.Package{
			Name:     name,
			Version:  strings.TrimPrefix(info.Version, "=="),
			Type:     config.PkgTypePip,
			LayerIdx: layerIdx,
			FilePath: path,
		})
	}

	return packages, nil
}

func parsePackageLockJSON(content []byte, layerIdx int, path string) ([]config.Package, error) {
	var data struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(content, &data); err != nil {
		return nil, err
	}

	var packages []config.Package

	for pkgPath, info := range data.Packages {
		name := pkgPath
		if strings.HasPrefix(pkgPath, "node_modules/") {
			name = strings.TrimPrefix(pkgPath, "node_modules/")
		}
		if name != "" && info.Version != "" {
			packages = append(packages, config.Package{
				Name:     name,
				Version:  info.Version,
				Type:     config.PkgTypeNpm,
				LayerIdx: layerIdx,
				FilePath: path,
			})
		}
	}

	return packages, nil
}

func parseYarnLock(content []byte, layerIdx int, path string) ([]config.Package, error) {
	var packages []config.Package

	scanner := bufio.NewScanner(bytes.NewReader(content))
	var currentName string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasSuffix(line, ":") && strings.Contains(line, "@") {
			parts := strings.SplitN(line, "@", 2)
			if len(parts) >= 1 {
				currentName = strings.Trim(strings.TrimSpace(parts[0]), `"`)
			}
		} else if strings.Contains(line, "version \"") && currentName != "" {
			if idx := strings.Index(line, "\""); idx != -1 {
				version := strings.Trim(line[idx+1:], "\"")
				packages = append(packages, config.Package{
					Name:     currentName,
					Version:  version,
					Type:     config.PkgTypeNpm,
					LayerIdx: layerIdx,
					FilePath: path,
				})
				currentName = ""
			}
		}
	}

	return packages, scanner.Err()
}

func parseGoSum(content []byte, layerIdx int, path string) ([]config.Package, error) {
	var packages []config.Package

	scanner := bufio.NewScanner(bytes.NewReader(content))
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			name := parts[0]
			version := strings.TrimSuffix(parts[1], "/go.mod")
			key := fmt.Sprintf("%s@%s", name, version)
			if !seen[key] {
				seen[key] = true
				packages = append(packages, config.Package{
					Name:     name,
					Version:  version,
					Type:     config.PkgTypeGo,
					LayerIdx: layerIdx,
					FilePath: path,
				})
			}
		}
	}

	return packages, scanner.Err()
}

func parsePomXML(content []byte, layerIdx int, path string) ([]config.Package, error) {
	var packages []config.Package

	scanner := bufio.NewScanner(bytes.NewReader(content))
	var groupId, artifactId, version string
	inDependency := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "<dependency>") {
			inDependency = true
			groupId, artifactId, version = "", "", ""
		} else if strings.Contains(line, "</dependency>") {
			inDependency = false
			if groupId != "" && artifactId != "" {
				name := fmt.Sprintf("%s:%s", groupId, artifactId)
				packages = append(packages, config.Package{
					Name:     name,
					Version:  version,
					Type:     config.PkgTypeMaven,
					LayerIdx: layerIdx,
					FilePath: path,
				})
			}
		} else if inDependency {
			if strings.Contains(line, "<groupId>") {
				groupId = extractXMLValue(line, "groupId")
			} else if strings.Contains(line, "<artifactId>") {
				artifactId = extractXMLValue(line, "artifactId")
			} else if strings.Contains(line, "<version>") {
				version = extractXMLValue(line, "version")
			}
		}
	}

	return packages, scanner.Err()
}

func extractXMLValue(line, tag string) string {
	start := fmt.Sprintf("<%s>", tag)
	end := fmt.Sprintf("</%s>", tag)
	if sIdx := strings.Index(line, start); sIdx != -1 {
		if eIdx := strings.Index(line, end); eIdx != -1 {
			return strings.TrimSpace(line[sIdx+len(start) : eIdx])
		}
	}
	return ""
}

func parseGradleLockfile(content []byte, layerIdx int, path string) ([]config.Package, error) {
	var packages []config.Package

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			name := fmt.Sprintf("%s:%s", parts[0], parts[1])
			version := parts[2]
			packages = append(packages, config.Package{
				Name:     name,
				Version:  version,
				Type:     config.PkgTypeMaven,
				LayerIdx: layerIdx,
				FilePath: path,
			})
		}
	}

	return packages, scanner.Err()
}

func GetDependencyFiles() []string {
	return []string{
		"**/requirements.txt",
		"**/Pipfile.lock",
		"**/package-lock.json",
		"**/yarn.lock",
		"**/go.sum",
		"**/pom.xml",
		"**/gradle.lockfile",
	}
}
