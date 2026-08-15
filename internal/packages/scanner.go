package packages

import (
	"bufio"
	"bytes"
	"strings"

	"imgscan/internal/config"
)

type PackageScanner interface {
	Scan(content []byte, layerIdx int) ([]config.Package, error)
}

type Scanner struct {
	fileLayerMap map[string]int
}

func NewScanner(fileLayerMap map[string]int) *Scanner {
	return &Scanner{
		fileLayerMap: fileLayerMap,
	}
}

func (s *Scanner) ScanOSPackages(fileContentMap map[string][]byte) []config.Package {
	var packages []config.Package

	for path, content := range fileContentMap {
		layerIdx := s.fileLayerMap[path]

		switch {
		case strings.HasSuffix(path, "var/lib/dpkg/status"):
			if pkgs, err := parseDPKGStatus(content, layerIdx); err == nil {
				packages = append(packages, pkgs...)
			}
		case strings.HasSuffix(path, "lib/apk/db/installed"):
			if pkgs, err := parseAPKInstalled(content, layerIdx); err == nil {
				packages = append(packages, pkgs...)
			}
		case strings.Contains(path, "var/lib/rpm"):
			if pkgs, err := parseRPMPackages(content, layerIdx); err == nil {
				packages = append(packages, pkgs...)
			}
		}
	}

	return packages
}

func parseDPKGStatus(content []byte, layerIdx int) ([]config.Package, error) {
	var packages []config.Package

	scanner := bufio.NewScanner(bytes.NewReader(content))
	pkg := config.Package{Type: config.PkgTypeDeb, LayerIdx: layerIdx}

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if pkg.Name != "" && pkg.Version != "" {
				pkg.DependsOn = parseDependsList(pkg.Depends)
				packages = append(packages, pkg)
			}
			pkg = config.Package{Type: config.PkgTypeDeb, LayerIdx: layerIdx}
			continue
		}

		if strings.HasPrefix(line, "Package: ") {
			pkg.Name = strings.TrimPrefix(line, "Package: ")
		} else if strings.HasPrefix(line, "Version: ") {
			pkg.Version = strings.TrimPrefix(line, "Version: ")
		} else if strings.HasPrefix(line, "Maintainer: ") {
			pkg.Supplier = strings.TrimPrefix(line, "Maintainer: ")
		} else if strings.HasPrefix(line, "Homepage: ") {
			pkg.Homepage = strings.TrimPrefix(line, "Homepage: ")
		} else if strings.HasPrefix(line, "License: ") {
			pkg.License = strings.TrimPrefix(line, "License: ")
		} else if strings.HasPrefix(line, "Architecture: ") {
			pkg.Architecture = strings.TrimPrefix(line, "Architecture: ")
		} else if strings.HasPrefix(line, "Depends: ") {
			pkg.Depends = strings.Split(strings.TrimPrefix(line, "Depends: "), ", ")
		} else if strings.HasPrefix(line, "Source: ") {
			pkg.SourceInfo = strings.TrimPrefix(line, "Source: ")
		}
	}

	if pkg.Name != "" && pkg.Version != "" {
		pkg.DependsOn = parseDependsList(pkg.Depends)
		packages = append(packages, pkg)
	}

	return packages, scanner.Err()
}

func parseDependsList(depends []string) []string {
	var names []string
	for _, d := range depends {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		name := d
		if idx := strings.IndexAny(name, " ("); idx != -1 {
			name = strings.TrimSpace(name[:idx])
		}
		if name != "" && name != "or" && !strings.HasPrefix(name, "${") {
			names = append(names, name)
		}
	}
	return names
}

func parseAPKInstalled(content []byte, layerIdx int) ([]config.Package, error) {
	var packages []config.Package

	scanner := bufio.NewScanner(bytes.NewReader(content))
	pkg := config.Package{Type: config.PkgTypeAPK, LayerIdx: layerIdx}

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if pkg.Name != "" && pkg.Version != "" {
				packages = append(packages, pkg)
			}
			pkg = config.Package{Type: config.PkgTypeAPK, LayerIdx: layerIdx}
			continue
		}

		if strings.HasPrefix(line, "P:") {
			pkg.Name = strings.TrimPrefix(line, "P:")
		} else if strings.HasPrefix(line, "V:") {
			pkg.Version = strings.TrimPrefix(line, "V:")
		} else if strings.HasPrefix(line, "m:") {
			pkg.Supplier = strings.TrimPrefix(line, "m:")
		} else if strings.HasPrefix(line, "U:") {
			pkg.Homepage = strings.TrimPrefix(line, "U:")
		} else if strings.HasPrefix(line, "L:") {
			pkg.License = strings.TrimPrefix(line, "L:")
		} else if strings.HasPrefix(line, "A:") {
			pkg.Architecture = strings.TrimPrefix(line, "A:")
		} else if strings.HasPrefix(line, "o:") {
			pkg.SourceInfo = strings.TrimPrefix(line, "o:")
		} else if strings.HasPrefix(line, "D:") {
			deps := strings.Split(strings.TrimPrefix(line, "D:"), " ")
			for _, d := range deps {
				d = strings.TrimSpace(d)
				if d != "" {
					if idx := strings.IndexAny(d, " ><=~"); idx != -1 {
						d = strings.TrimSpace(d[:idx])
					}
					if d != "" {
						pkg.DependsOn = append(pkg.DependsOn, d)
					}
				}
			}
		}
	}

	if pkg.Name != "" && pkg.Version != "" {
		packages = append(packages, pkg)
	}

	return packages, scanner.Err()
}

func parseRPMPackages(content []byte, layerIdx int) ([]config.Package, error) {
	return nil, nil
}

func GetOSPackageFiles() []string {
	return []string{
		"var/lib/dpkg/status",
		"lib/apk/db/installed",
		"var/lib/rpm/Packages",
	}
}
