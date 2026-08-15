package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	dir        string
	policyPath string
	webhookURL string
	auditLog   string
	publicKey  string

	policyEngine *PolicyEngine
	policyMtime  time.Time

	watcher  *fsnotify.Watcher
	done     chan struct{}
	mu       sync.Mutex
	running  bool
}

type AuditEntry struct {
	Timestamp   string `json:"timestamp"`
	File        string `json:"file"`
	PassedCount int    `json:"passed_count"`
	ViolCount   int    `json:"violation_count"`
	Summary     string `json:"summary"`
	SignatureOK bool   `json:"signature_valid,omitempty"`
	SkipReason  string `json:"skip_reason,omitempty"`
}

type WebhookPayload struct {
	Timestamp  string           `json:"timestamp"`
	File       string           `json:"file"`
	Violations []PolicyRuleResult `json:"violations"`
	Passed     int              `json:"passed_count"`
	ViolCount  int              `json:"violation_count"`
}

func NewWatcher(dir, policyPath, webhookURL, auditLog, publicKey string) *Watcher {
	if auditLog == "" {
		auditLog = "./sbom-audit.log"
	}
	return &Watcher{
		dir:        dir,
		policyPath: policyPath,
		webhookURL: webhookURL,
		auditLog:   auditLog,
		publicKey:  publicKey,
		done:       make(chan struct{}),
	}
}

func (w *Watcher) Start() error {
	var err error
	w.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	if err := w.loadPolicy(); err != nil {
		return fmt.Errorf("failed to load initial policy: %w", err)
	}

	if err := w.watcher.Add(w.dir); err != nil {
		return fmt.Errorf("failed to watch directory %s: %w", w.dir, err)
	}

	if w.policyPath != "" {
		policyDir := filepath.Dir(w.policyPath)
		if err := w.watcher.Add(policyDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to watch policy directory: %v\n", err)
		}
		w.policyMtime = w.getPolicyMtime()
	}

	w.running = true
	fmt.Fprintf(os.Stderr, "SBOM Watch: 监控目录 %s\n", w.dir)
	fmt.Fprintf(os.Stderr, "策略文件: %s\n", w.policyPath)
	fmt.Fprintf(os.Stderr, "审计日志: %s\n", w.auditLog)
	fmt.Fprintf(os.Stderr, "按 Ctrl+C 退出\n\n")

	go w.eventLoop()

	sbomFiles := w.findSBOMFiles()
	if len(sbomFiles) > 0 {
		fmt.Fprintf(os.Stderr, "发现 %d 个现有SBOM文件, 正在评估...\n", len(sbomFiles))
		for _, f := range sbomFiles {
			w.evaluateFile(f)
		}
	}

	return nil
}

func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.running {
		return
	}
	w.running = false
	close(w.done)
	if w.watcher != nil {
		w.watcher.Close()
	}
	fmt.Fprintf(os.Stderr, "\nSBOM Watch: 已停止\n")
}

func (w *Watcher) eventLoop() {
	for {
		select {
		case <-w.done:
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			w.handleEvent(event)
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			fmt.Fprintf(os.Stderr, "Watcher error: %v\n", err)
		}
	}
}

func (w *Watcher) handleEvent(event fsnotify.Event) {
	if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
		if w.policyPath != "" && event.Name == w.policyPath {
			w.handlePolicyChange()
			return
		}

		if w.isSBOMFile(event.Name) {
			time.Sleep(500 * time.Millisecond)
			w.evaluateFile(event.Name)
		}
	}
}

func (w *Watcher) handlePolicyChange() {
	currentMtime := w.getPolicyMtime()
	if !currentMtime.After(w.policyMtime) {
		return
	}
	w.policyMtime = currentMtime

	oldEngine := w.policyEngine
	if err := w.loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ 策略文件格式错误, 继续使用上一有效版本: %v\n", err)
		w.policyEngine = oldEngine
		return
	}

	sbomFiles := w.findSBOMFiles()
	fmt.Fprintf(os.Stderr, "策略已更新, 重新评估%d个文件\n", len(sbomFiles))
	for _, f := range sbomFiles {
		w.evaluateFile(f)
	}
}

func (w *Watcher) loadPolicy() error {
	if w.policyPath == "" {
		w.policyEngine = &PolicyEngine{policy: nil}
		return nil
	}

	engine, err := NewPolicyEngine(w.policyPath)
	if err != nil {
		return err
	}
	w.policyEngine = engine
	return nil
}

func (w *Watcher) getPolicyMtime() time.Time {
	if w.policyPath == "" {
		return time.Time{}
	}
	info, err := os.Stat(w.policyPath)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

func (w *Watcher) isSBOMFile(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(name, ".json") ||
		strings.HasSuffix(name, ".spdx") ||
		strings.HasSuffix(name, ".cdx")
}

func (w *Watcher) findSBOMFiles() []string {
	var files []string
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return files
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(w.dir, entry.Name())
		if w.isSBOMFile(fullPath) {
			files = append(files, fullPath)
		}
	}
	return files
}

func (w *Watcher) evaluateFile(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", filePath, err)
		return
	}

	entry := AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		File:      filePath,
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		entry.SkipReason = fmt.Sprintf("invalid JSON: %v", err)
		w.logAudit(entry)
		return
	}

	if sigRaw, ok := rawMap["_ed25519_signature"]; ok && w.publicKey != "" {
		var sigB64 string
		if err := json.Unmarshal(sigRaw, &sigB64); err == nil && sigB64 != "" {
			contentData, _ := json.Marshal(rawMap)
			if err := VerifyEd25519(contentData, sigB64, w.publicKey); err != nil {
				entry.SkipReason = fmt.Sprintf("signature verification failed: %v", err)
				entry.SignatureOK = false
				w.logAudit(entry)
				fmt.Fprintf(os.Stderr, "⚠ 签名验证失败, 跳过: %s (%v)\n", filePath, err)
				return
			}
			entry.SignatureOK = true
		}
	}

	doc, err := LoadBaseline(data)
	if err != nil {
		entry.SkipReason = fmt.Sprintf("failed to parse SBOM: %v", err)
		w.logAudit(entry)
		return
	}

	if w.policyEngine == nil || w.policyEngine.policy == nil {
		entry.PassedCount = 0
		entry.ViolCount = 0
		entry.Summary = "no policy loaded"
		w.logAudit(entry)
		return
	}

	policyResult := w.policyEngine.Evaluate(doc)
	entry.PassedCount = len(policyResult.Passed)
	entry.ViolCount = len(policyResult.Failed)

	if entry.ViolCount > 0 {
		var summaries []string
		for _, f := range policyResult.Failed {
			summaries = append(summaries, fmt.Sprintf("[%s] %s", f.RuleID, f.Details))
		}
		entry.Summary = strings.Join(summaries, "; ")
	} else {
		entry.Summary = "all checks passed"
	}

	w.logAudit(entry)

	fmt.Fprintf(os.Stderr, "[%s] %s: %d passed, %d violations\n",
		entry.Timestamp, filepath.Base(filePath), entry.PassedCount, entry.ViolCount)

	if entry.ViolCount > 0 {
		for _, v := range policyResult.Failed {
			fmt.Fprintf(os.Stderr, "  ✗ [%s] %s: %s\n", v.RuleID, v.RuleName, v.Details)
		}
	}

	if entry.ViolCount > 0 && w.webhookURL != "" {
		w.sendWebhook(entry, policyResult.Failed)
	}
}

func (w *Watcher) logAudit(entry AuditEntry) {
	line, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling audit entry: %v\n", err)
		return
	}

	f, err := os.OpenFile(w.auditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening audit log: %v\n", err)
		return
	}
	defer f.Close()

	f.Write(append(line, '\n'))
}

func (w *Watcher) sendWebhook(entry AuditEntry, violations []PolicyRuleResult) {
	payload := WebhookPayload{
		Timestamp:  entry.Timestamp,
		File:       entry.File,
		Violations: violations,
		Passed:     entry.PassedCount,
		ViolCount:  entry.ViolCount,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling webhook payload: %v\n", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(w.webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Webhook delivery failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "Webhook returned status %d\n", resp.StatusCode)
	}
}
