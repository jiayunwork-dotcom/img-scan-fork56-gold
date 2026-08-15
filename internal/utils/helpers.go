package utils

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"imgscan/internal/config"
)

func TruncateString(s string, maxLen int) string {
	if len(s) < maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func GetRegistryAuth(imageRef string, auth config.RegistryAuth) (authn.Authenticator, error) {
	if auth.Token != "" {
		return &authn.Bearer{Token: auth.Token}, nil
	}
	if auth.Username != "" && auth.Password != "" {
		return &authn.Basic{Username: auth.Username, Password: auth.Password}, nil
	}
	return authn.Anonymous, nil
}

func PullImage(imageRef, destDir string, auth authn.Authenticator) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("invalid image reference: %w", err)
	}

	img, err := remote.Image(ref, remote.WithAuth(auth))
	if err != nil {
		return fmt.Errorf("failed to fetch image: %w", err)
	}

	return saveImageAsOCI(img, destDir)
}

func saveImageAsOCI(img v1.Image, destDir string) error {
	if err := os.MkdirAll(filepath.Join(destDir, "blobs", "sha256"), 0755); err != nil {
		return err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return err
	}

	configData, err := img.RawConfigFile()
	if err != nil {
		return err
	}
	configHash, err := v1.NewHash(manifest.Config.Digest.String())
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(destDir, "blobs", "sha256", configHash.Hex), configData, 0644); err != nil {
		return err
	}

	layers, err := img.Layers()
	if err != nil {
		return err
	}
	for _, layer := range layers {
		layerData, err := layer.Compressed()
		if err != nil {
			continue
		}
		defer layerData.Close()
		digest, err := layer.Digest()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(layerData)
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(destDir, "blobs", "sha256", digest.Hex), data, 0644); err != nil {
			continue
		}
	}

	manifestJSON, _ := img.RawManifest()
	_ = os.WriteFile(filepath.Join(destDir, "blobs", "sha256", "manifest"), manifestJSON, 0644)

	indexJSON := fmt.Sprintf(`{
  "schemaVersion": 2,
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:manifest",
      "size": %d
    }
  ]
}`, len(manifestJSON))

	return os.WriteFile(filepath.Join(destDir, "index.json"), []byte(indexJSON), 0644)
}

func GetFileFromLayers(layers []config.ImageLayer, filePath string, tempDir string) ([]byte, error) {
	filePath = filepath.Clean(filePath)
	if strings.HasPrefix(filePath, "/") {
		filePath = strings.TrimPrefix(filePath, "/")
	}

	layerTarPath := filepath.Join(tempDir, "layers")
	if err := os.MkdirAll(layerTarPath, 0755); err != nil {
		return nil, err
	}

	for i := len(layers) - 1; i >= 0; i-- {
		layer := layers[i]
		for _, f := range layer.AddedFiles {
			if f == filePath {
				return []byte("file_exists"), nil
			}
		}
		for _, f := range layer.ModifiedFiles {
			if f == filePath {
				return []byte("file_exists"), nil
			}
		}
		for _, f := range layer.DeletedFiles {
			if f == filePath {
				return nil, fmt.Errorf("file deleted in layer %d", i)
			}
		}
	}

	return nil, fmt.Errorf("file not found: %s", filePath)
}

func ExtractFileFromTar(layerContent []byte, filePath string, compressed bool) ([]byte, error) {
	var tr *tar.Reader

	if compressed {
		gzr, err := gzip.NewReader(strings.NewReader(string(layerContent)))
		if err != nil {
			return nil, err
		}
		defer gzr.Close()
		tr = tar.NewReader(gzr)
	} else {
		tr = tar.NewReader(strings.NewReader(string(layerContent)))
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		name := filepath.Clean(header.Name)
		if strings.HasPrefix(name, "./") {
			name = strings.TrimPrefix(name, "./")
		}

		if name == filePath {
			return io.ReadAll(tr)
		}
	}

	return nil, fmt.Errorf("file not found in layer")
}

func ContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func MapKVToSlice(m map[string]string) [][2]string {
	result := make([][2]string, 0, len(m))
	for k, v := range m {
		result = append(result, [2]string{k, v})
	}
	return result
}

func ParseBool(s string) bool {
	s = strings.ToLower(s)
	return s == "true" || s == "1" || s == "yes"
}

func GetEnvWithDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func NowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func Retry(ctx context.Context, fn func() error, maxRetries int, backoff time.Duration) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		if err = fn(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff * time.Duration(i+1)):
		}
	}
	return err
}

func ChunkStrings(slice []string, chunkSize int) [][]string {
	var chunks [][]string
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	return chunks
}

func SaveTarImage(img v1.Image, path string) error {
	return tarball.WriteToFile(path, nil, img)
}
