package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"imgscan/internal/config"
	"imgscan/internal/utils"
)

type ImageParser struct {
	layers           []config.ImageLayer
	fileMap          map[string]int
	fileContentCache map[string][]byte
	tempDir          string
}

func NewImageParser() *ImageParser {
	return &ImageParser{
		fileMap:          make(map[string]int),
		fileContentCache: make(map[string][]byte),
	}
}

func (p *ImageParser) Parse(input string, inputType config.ImageInputType, auth config.RegistryAuth) (*config.ScanResult, error) {
	var err error
	p.tempDir, err = os.MkdirTemp("", "imgscan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(p.tempDir)

	var layers []config.ImageLayer
	var configJSON []byte

	switch inputType {
	case config.InputTypeTar:
		layers, configJSON, err = p.parseTar(input)
	case config.InputTypeOCI:
		layers, configJSON, err = p.parseOCI(input)
	case config.InputTypeRemote:
		layers, configJSON, err = p.parseRemote(input, auth)
	default:
		return nil, fmt.Errorf("unknown input type: %s", inputType)
	}

	if err != nil {
		return nil, err
	}

	p.layers = layers

	result := &config.ScanResult{
		ImageName: input,
		Layers:    layers,
	}

	if len(configJSON) > 0 {
		p.parseConfig(configJSON, result)
	}

	return result, nil
}

func (p *ImageParser) parseTar(path string) ([]config.ImageLayer, []byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open tar: %w", err)
	}
	defer file.Close()

	tr := tar.NewReader(file)

	type ManifestEntry struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}
	var manifestList []ManifestEntry
	var configJSON []byte
	allFiles := make(map[string][]byte)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("error reading tar: %w", err)
		}

		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}

		content, err := io.ReadAll(tr)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading file %s: %w", header.Name, err)
		}

		name := header.Name
		allFiles[name] = content

		if name == "manifest.json" {
			if err := json.Unmarshal(content, &manifestList); err != nil {
				return nil, nil, fmt.Errorf("failed to parse manifest: %w", err)
			}
		} else if strings.HasSuffix(name, ".json") && !strings.Contains(name, "/") {
			configJSON = content
		}
	}

	if len(manifestList) == 0 {
		return nil, nil, fmt.Errorf("no manifest found in tar")
	}

	manifest := manifestList[0]
	fmt.Printf("Debug: Found %d layers in manifest\n", len(manifest.Layers))
	fmt.Printf("Debug: Layer paths in manifest: %v\n", manifest.Layers)
	fmt.Printf("Debug: Total files in tar: %d\n", len(allFiles))

	layers := make([]config.ImageLayer, len(manifest.Layers))

	for i, layerPath := range manifest.Layers {
		layerContent, ok := findLayerContent(allFiles, layerPath)
		if !ok {
			fmt.Printf("Warning: Layer %s not found in tar\n", layerPath)
			fmt.Printf("Debug: Available files (first 20):\n")
			count := 0
			for k := range allFiles {
				if count < 20 {
					fmt.Printf("  - %s\n", k)
					count++
				}
			}
			continue
		}

		isCompressed := isLayerCompressed(layerPath)
		layer := p.parseLayer(i, layerContent, isCompressed)
		layers[i] = layer
		fmt.Printf("Debug: Layer %d - Added: %d, Modified: %d, Deleted: %d\n",
			i, len(layer.AddedFiles), len(layer.ModifiedFiles), len(layer.DeletedFiles))
	}

	return layers, configJSON, nil
}

func findLayerContent(allFiles map[string][]byte, layerPath string) ([]byte, bool) {
	if content, ok := allFiles[layerPath]; ok {
		return content, true
	}

	alternatePaths := []string{
		layerPath,
		strings.TrimPrefix(layerPath, "blobs/sha256/") + "/layer.tar",
	}

	for _, p := range alternatePaths {
		if content, ok := allFiles[p]; ok {
			return content, true
		}
	}

	for name, content := range allFiles {
		if strings.Contains(name, extractHash(layerPath)) {
			if strings.HasSuffix(name, "layer.tar") || strings.HasPrefix(name, "blobs/") {
				return content, true
			}
		}
	}

	return nil, false
}

func extractHash(path string) string {
	hash := path
	if idx := strings.LastIndex(hash, "/"); idx != -1 {
		hash = hash[idx+1:]
	}
	if idx := strings.Index(hash, ":"); idx != -1 {
		hash = hash[:idx]
	}
	return hash
}

func isLayerCompressed(layerPath string) bool {
	return strings.HasSuffix(layerPath, "layer.tar") ||
		strings.HasSuffix(layerPath, ".tar.gz") ||
		strings.HasPrefix(layerPath, "blobs/")
}

func (p *ImageParser) parseOCI(path string) ([]config.ImageLayer, []byte, error) {
	indexPath := filepath.Join(path, "index.json")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read index.json: %w", err)
	}

	var index struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, nil, fmt.Errorf("failed to parse index.json: %w", err)
	}

	if len(index.Manifests) == 0 {
		return nil, nil, fmt.Errorf("no manifests found")
	}

	manifestDigest := strings.TrimPrefix(index.Manifests[0].Digest, "sha256:")
	manifestPath := filepath.Join(path, "blobs", "sha256", manifestDigest)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	configDigest := strings.TrimPrefix(manifest.Config.Digest, "sha256:")
	configPath := filepath.Join(path, "blobs", "sha256", configDigest)
	configJSON, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config: %w", err)
	}

	layers := make([]config.ImageLayer, len(manifest.Layers))

	for i, layer := range manifest.Layers {
		layerDigest := strings.TrimPrefix(layer.Digest, "sha256:")
		layerPath := filepath.Join(path, "blobs", "sha256", layerDigest)
		content, err := os.ReadFile(layerPath)
		if err != nil {
			continue
		}

		layer := p.parseLayer(i, content, true)
		layers[i] = layer
	}

	return layers, configJSON, nil
}

func (p *ImageParser) parseRemote(imageRef string, auth config.RegistryAuth) ([]config.ImageLayer, []byte, error) {
	authConfig, err := utils.GetRegistryAuth(imageRef, auth)
	if err != nil {
		return nil, nil, err
	}

	pullDir := filepath.Join(p.tempDir, "pulled")
	if err := os.MkdirAll(pullDir, 0755); err != nil {
		return nil, nil, err
	}

	if err := utils.PullImage(imageRef, pullDir, authConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to pull image: %w", err)
	}

	return p.parseOCI(pullDir)
}

func (p *ImageParser) parseLayer(index int, content []byte, compressed bool) config.ImageLayer {
	layer := config.ImageLayer{
		Index:  index,
		Digest: fmt.Sprintf("layer-%d", index),
	}

	var tr *tar.Reader

	if compressed {
		gzr, err := gzip.NewReader(bytes.NewReader(content))
		if err != nil {
			fmt.Printf("Warning: Failed to decompress layer %d: %v\n", index, err)
			return layer
		}
		defer gzr.Close()
		tr = tar.NewReader(gzr)
	} else {
		tr = tar.NewReader(bytes.NewReader(content))
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		name := header.Name
		if strings.HasPrefix(name, "./") {
			name = strings.TrimPrefix(name, "./")
		}
		name = filepath.Clean(name)

		if name == "." || name == "" {
			continue
		}

		if strings.HasPrefix(filepath.Base(name), ".wh.") {
			baseDir := filepath.Dir(name)
			origName := strings.TrimPrefix(filepath.Base(name), ".wh.")
			if origName == ".wh..wh..opq" {
				p.handleOpaqueWhiteout(baseDir, &layer)
			} else {
				deletedPath := filepath.Join(baseDir, origName)
				layer.DeletedFiles = append(layer.DeletedFiles, deletedPath)
				delete(p.fileMap, deletedPath)
			}
			continue
		}

		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			if isRelevantForScan(name) {
				fileContent, err := io.ReadAll(tr)
				if err == nil {
					p.fileContentCache[name] = fileContent
				}
			}
		}

		if prevIdx, exists := p.fileMap[name]; exists {
			if prevIdx != index {
				layer.ModifiedFiles = append(layer.ModifiedFiles, name)
			}
		} else {
			layer.AddedFiles = append(layer.AddedFiles, name)
		}
		p.fileMap[name] = index
	}

	return layer
}

func isRelevantForScan(path string) bool {
	relevantSuffixes := []string{
		"var/lib/dpkg/status",
		"lib/apk/db/installed",
		"var/lib/rpm/Packages",
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
	return isLicenseFile(path)
}

func isLicenseFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	licenseNames := []string{"license", "copying", "notice"}
	licenseExts := []string{"", ".txt", ".md", ".rst", ".html"}
	for _, name := range licenseNames {
		for _, ext := range licenseExts {
			if base == name+ext {
				return true
			}
		}
	}
	return false
}

func (p *ImageParser) FindLicenseFiles() map[string][]byte {
	result := make(map[string][]byte)
	for path, content := range p.fileContentCache {
		if isLicenseFile(path) {
			result[path] = content
		}
	}
	return result
}

func (p *ImageParser) GetAllCachedFiles() map[string][]byte {
	return p.fileContentCache
}

func (p *ImageParser) handleOpaqueWhiteout(dir string, layer *config.ImageLayer) {
	for file := range p.fileMap {
		if strings.HasPrefix(file, dir+string(filepath.Separator)) || file == dir {
			layer.DeletedFiles = append(layer.DeletedFiles, file)
			delete(p.fileMap, file)
		}
	}
}

func (p *ImageParser) parseConfig(configJSON []byte, result *config.ScanResult) {
	var imgConfig struct {
		Config struct {
			User string `json:"User"`
			Env  []string `json:"Env"`
		} `json:"config"`
		History []struct {
			CreatedBy string `json:"created_by"`
		} `json:"history"`
	}
	if err := json.Unmarshal(configJSON, &imgConfig); err != nil {
		return
	}

	for i, hist := range imgConfig.History {
		if i < len(result.Layers) {
			result.Layers[i].Digest = fmt.Sprintf("history-%d: %s", i, utils.TruncateString(hist.CreatedBy, 50))
		}
	}
}

func (p *ImageParser) GetFileContent(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	if strings.HasPrefix(cleanPath, "/") {
		cleanPath = strings.TrimPrefix(cleanPath, "/")
	}
	if content, ok := p.fileContentCache[cleanPath]; ok {
		return content, nil
	}
	return nil, fmt.Errorf("file not found in cache: %s", cleanPath)
}

func (p *ImageParser) FindFiles(pattern string) []string {
	var matches []string
	for file := range p.fileMap {
		if ok, _ := filepath.Match(pattern, filepath.Base(file)); ok {
			matches = append(matches, file)
		}
	}
	return matches
}

func (p *ImageParser) GetFileLayer(path string) int {
	if idx, ok := p.fileMap[path]; ok {
		return idx
	}
	return -1
}
