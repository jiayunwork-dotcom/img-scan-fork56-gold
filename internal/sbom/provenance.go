package sbom

import (
	"fmt"
	"strings"
	"sync"

	"imgscan/internal/config"
)

type ProvenanceBuilder struct {
	packages    []config.Package
	fileMap     map[string]int
	depGraph    map[string][]string
	mu          sync.Mutex
}

func NewProvenanceBuilder(packages []config.Package, fileMap map[string]int) *ProvenanceBuilder {
	return &ProvenanceBuilder{
		packages: packages,
		fileMap:  fileMap,
		depGraph: make(map[string][]string),
	}
}

func (pb *ProvenanceBuilder) BuildAll() map[string]ProvenanceInfo {
	pb.buildDependencyGraph()

	result := make(map[string]ProvenanceInfo)
	var mu sync.Mutex

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, pkg := range pb.packages {
		wg.Add(1)
		sem <- struct{}{}
		go func(p config.Package) {
			defer wg.Done()
			defer func() { <-sem }()

			prov := pb.buildProvenance(p)
			key := PkgID(p.Name, p.Version, p.Type)
			mu.Lock()
			result[key] = prov
			mu.Unlock()
		}(pkg)
	}

	wg.Wait()
	return result
}

func (pb *ProvenanceBuilder) buildDependencyGraph() {
	for _, pkg := range pb.packages {
		key := pkg.Name
		if len(pkg.DependsOn) > 0 {
			pb.depGraph[key] = pkg.DependsOn
		}
	}
}

func (pb *ProvenanceBuilder) buildProvenance(pkg config.Package) ProvenanceInfo {
	installMethod := pb.detectInstallMethod(pkg)
	isDirect := pb.isDirectDependency(pkg)
	depPath := pb.buildDependencyPath(pkg)

	return ProvenanceInfo{
		LayerIndex:     pkg.LayerIdx,
		InstallMethod:  installMethod,
		DependencyPath: depPath,
		IsDirect:       isDirect,
	}
}

func (pb *ProvenanceBuilder) detectInstallMethod(pkg config.Package) string {
	switch pkg.Type {
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

func (pb *ProvenanceBuilder) isDirectDependency(pkg config.Package) bool {
	for _, other := range pb.packages {
		if other.Name == pkg.Name {
			continue
		}
		for _, dep := range other.DependsOn {
			if dep == pkg.Name {
				return false
			}
		}
	}

	if pkg.Type == config.PkgTypeDeb || pkg.Type == config.PkgTypeRPM || pkg.Type == config.PkgTypeAPK {
		return pb.isLikelyBaseImagePackage(pkg)
	}

	return true
}

func (pb *ProvenanceBuilder) isLikelyBaseImagePackage(pkg config.Package) bool {
	if pkg.LayerIdx == 0 {
		return true
	}

	basePackages := map[string]bool{
		"libc6": true, "libssl": true, "openssl": true, "ca-certificates": true,
		"tzdata": true, "dpkg": true, "apt": true, "base-files": true,
		"netbase": true, "libc-bin": true, "libcrypt1": true,
		"alpine-baselayout": true, "alpine-keys": true, "musl": true,
		"busybox": true, "apk-tools": true,
	}

	name := pkg.Name
	for prefix := range basePackages {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func (pb *ProvenanceBuilder) buildDependencyPath(pkg config.Package) []string {
	visited := make(map[string]bool)
	path := []string{pkg.Name}
	pb.traceDependencyPath(pkg.Name, visited, &path)

	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}

	return path
}

func (pb *ProvenanceBuilder) traceDependencyPath(pkgName string, visited map[string]bool, path *[]string) bool {
	if visited[pkgName] {
		return false
	}
	visited[pkgName] = true

	for _, other := range pb.packages {
		if other.Name == pkgName {
			continue
		}
		for _, dep := range other.DependsOn {
			if dep == pkgName {
				*path = append(*path, other.Name)
				if pb.traceDependencyPath(other.Name, visited, path) {
					return true
				}
			}
		}
	}

	return false
}

func (pb *ProvenanceBuilder) GetDependencyTree() map[string]*DependencyNode {
	tree := make(map[string]*DependencyNode)

	for _, pkg := range pb.packages {
		node := &DependencyNode{
			PackageName: pkg.Name,
			Version:     pkg.Version,
			DependsOn:   pkg.DependsOn,
		}
		tree[pkg.Name] = node
	}

	return tree
}

func FormatDependencyPath(path []string) string {
	if len(path) == 0 {
		return ""
	}
	if len(path) == 1 {
		return path[0]
	}
	return strings.Join(path, " <- ")
}

func FormatProvenance(prov ProvenanceInfo) string {
	layerStr := fmt.Sprintf("layer:%d", prov.LayerIndex)
	methodStr := prov.InstallMethod
	pathStr := FormatDependencyPath(prov.DependencyPath)
	directStr := "transitive"
	if prov.IsDirect {
		directStr = "direct"
	}

	parts := []string{layerStr, methodStr, directStr}
	if pathStr != "" {
		parts = append(parts, pathStr)
	}
	return strings.Join(parts, " | ")
}
