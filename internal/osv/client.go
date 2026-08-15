package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"imgscan/internal/config"
)

const (
	OSVAPIEndpoint = "https://api.osv.dev/v1/query"
	CacheDir       = "imgscan_cache"
	CacheFile      = "osv_cache.json"
	DefaultTTL     = 24 * time.Hour
)

type Client struct {
	cache     map[string]cacheEntry
	cacheFile string
	cacheTTL  time.Duration
	mu        sync.Mutex
	client    *http.Client
}

type cacheEntry struct {
	Response   []Vulnerability
	Expiration time.Time
}

type OSVQuery struct {
	Package  OSVPackage `json:"package"`
	Version  string     `json:"version"`
}

type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OSVResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

type Vulnerability struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	Details    string   `json:"details"`
	Modified   string   `json:"modified"`
	Published  string   `json:"published"`
	Aliases    []string `json:"aliases"`
	Related    []string `json:"related"`
	Severity   []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
			Purl      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

func NewClient(cacheDir string, cacheTTL int) (*Client, error) {
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		cacheDir = filepath.Join(home, ".cache", CacheDir)
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}

	c := &Client{
		cache:     make(map[string]cacheEntry),
		cacheFile: filepath.Join(cacheDir, CacheFile),
		cacheTTL:  time.Duration(cacheTTL) * time.Hour,
		client:    &http.Client{Timeout: 30 * time.Second},
	}

	if c.cacheTTL == 0 {
		c.cacheTTL = DefaultTTL
	}

	if err := c.loadCache(); err != nil {
		fmt.Printf("Warning: failed to load cache: %v\n", err)
	}

	return c, nil
}

func (c *Client) loadCache() error {
	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var cacheData struct {
		Entries map[string]cacheEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &cacheData); err != nil {
		return err
	}

	c.cache = cacheData.Entries
	return nil
}

func (c *Client) saveCache() error {
	cacheData := struct {
		Entries map[string]cacheEntry `json:"entries"`
	}{
		Entries: c.cache,
	}

	data, err := json.MarshalIndent(cacheData, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(c.cacheFile, data, 0644)
}

func (c *Client) getCacheKey(pkg config.Package) string {
	return fmt.Sprintf("%s:%s:%s", pkg.Type, pkg.Name, pkg.Version)
}

func (c *Client) Query(pkg config.Package) ([]config.Vulnerability, error) {
	cacheKey := c.getCacheKey(pkg)

	c.mu.Lock()
	if entry, ok := c.cache[cacheKey]; ok && time.Now().Before(entry.Expiration) {
		c.mu.Unlock()
		result := make([]config.Vulnerability, len(entry.Response))
		for i, v := range entry.Response {
			result[i] = c.convertVulnerability(v, pkg)
		}
		return result, nil
	}
	c.mu.Unlock()

	ecosystem := getEcosystem(pkg.Type)
	if ecosystem == "" {
		return nil, nil
	}

	query := OSVQuery{
		Package: OSVPackage{
			Name:      pkg.Name,
			Ecosystem: ecosystem,
		},
		Version: pkg.Version,
	}

	vulns, err := c.queryOSV(query)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[cacheKey] = cacheEntry{
		Response:   vulns,
		Expiration: time.Now().Add(c.cacheTTL),
	}
	c.mu.Unlock()

	result := make([]config.Vulnerability, len(vulns))
	for i, v := range vulns {
		result[i] = c.convertVulnerability(v, pkg)
	}

	return result, nil
}

func (c *Client) queryOSV(query OSVQuery) ([]Vulnerability, error) {
	data, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", OSVAPIEndpoint, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(body))
	}

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, err
	}

	return osvResp.Vulns, nil
}

func (c *Client) convertVulnerability(v Vulnerability, pkg config.Package) config.Vulnerability {
	severity := config.SeverityLow
	cvssScore := 0.0

	for _, s := range v.Severity {
		if score, err := parseCVSS(s.Score); err == nil {
			cvssScore = score
			severity = getSeverityFromCVSS(score)
		}
	}

	if severity == config.SeverityLow && strings.Contains(v.ID, "CVE-2024") {
	}

	fixedVersion := ""
	for _, affected := range v.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					fixedVersion = event.Fixed
					break
				}
			}
		}
	}

	cveID := v.ID
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveID = alias
			break
		}
	}

	return config.Vulnerability{
		ID:              v.ID,
		Title:           v.Title,
		CVE:             cveID,
		Severity:        severity,
		PackageName:     pkg.Name,
		PackageVersion:  pkg.Version,
		FixedVersion:    fixedVersion,
		Description:     v.Summary,
		LayerIdx:        pkg.LayerIdx,
		CVSS:            cvssScore,
	}
}

func (c *Client) QueryBatch(packages []config.Package) []config.Vulnerability {
	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		vulns        []config.Vulnerability
		sem          = make(chan struct{}, 10)
	)

	for _, pkg := range packages {
		if pkg.Version == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p config.Package) {
			defer wg.Done()
			defer func() { <-sem }()

			if result, err := c.Query(p); err == nil {
				mu.Lock()
				vulns = append(vulns, result...)
				mu.Unlock()
			}
		}(pkg)
	}

	wg.Wait()
	_ = c.saveCache()

	return vulns
}

func getEcosystem(pkgType config.PackageType) string {
	switch pkgType {
	case config.PkgTypeDeb:
		return "Debian"
	case config.PkgTypeRPM:
		return ""
	case config.PkgTypeAPK:
		return "Alpine"
	case config.PkgTypePip:
		return "PyPI"
	case config.PkgTypeNpm:
		return "npm"
	case config.PkgTypeGo:
		return "Go"
	case config.PkgTypeMaven:
		return "Maven"
	default:
		return ""
	}
}

func parseCVSS(score string) (float64, error) {
	parts := strings.Split(score, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "CVSS:3.") {
			continue
		}
		if strings.HasPrefix(part, "SCORE:") {
			var f float64
			_, err := fmt.Sscanf(part, "SCORE:%f", &f)
			return f, err
		}
	}
	return 0, fmt.Errorf("no score found")
}

func getSeverityFromCVSS(score float64) config.Severity {
	switch {
	case score >= 9.0:
		return config.SeverityCritical
	case score >= 7.0:
		return config.SeverityHigh
	case score >= 4.0:
		return config.SeverityMedium
	default:
		return config.SeverityLow
	}
}

func (c *Client) Close() error {
	return c.saveCache()
}
