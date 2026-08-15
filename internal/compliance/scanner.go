package compliance

import (
	"path/filepath"
	"strings"

	"imgscan/internal/config"
)

type Scanner struct {
	fileMap    map[string]int
	packages   []config.Package
	imageUser  string
	history    []string
}

func NewScanner(fileMap map[string]int, packages []config.Package, imageUser string, history []string) *Scanner {
	return &Scanner{
		fileMap:   fileMap,
		packages:  packages,
		imageUser: imageUser,
		history:   history,
	}
}

func (s *Scanner) Scan() []config.ComplianceIssue {
	var issues []config.ComplianceIssue

	if issue := s.checkRootUser(); issue != nil {
		issues = append(issues, *issue)
	}

	if sensitive := s.checkSensitiveFiles(); len(sensitive) > 0 {
		issues = append(issues, sensitive...)
	}

	if suid := s.checkSUIDFiles(); len(suid) > 0 {
		issues = append(issues, suid...)
	}

	if unwanted := s.checkUnwantedPackages(); len(unwanted) > 0 {
		issues = append(issues, unwanted...)
	}

	if latest := s.checkLatestTag(); latest != nil {
		issues = append(issues, *latest)
	}

	return issues
}

func (s *Scanner) checkRootUser() *config.ComplianceIssue {
	if s.imageUser == "" || s.imageUser == "root" || s.imageUser == "0" {
		return &config.ComplianceIssue{
			RuleID:      "CIS-DI-0001",
			RuleName:    "Root User Check",
			Severity:    config.SeverityHigh,
			Description: "Container should not run as root user. Use USER instruction to switch to a non-root user.",
			Evidence:    []string{"Image config shows user is root or not set"},
		}
	}
	return nil
}

func (s *Scanner) checkSensitiveFiles() []config.ComplianceIssue {
	patterns := []struct {
		name        string
		description string
		patterns    []string
	}{
		{
			name:        "SSH Private Keys",
			description: "SSH private keys found in image",
			patterns:    []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "ssh_host_*_key"},
		},
		{
			name:        "Password Files",
			description: "Potential password files found",
			patterns:    []string{".password", "password.txt", "credentials", "secrets"},
		},
		{
			name:        "Cloud Credentials",
			description: "Cloud provider credentials found",
			patterns:    []string{".aws/credentials", ".azure/credentials", "gcloud/credentials.json", "service_account.json"},
		},
		{
			name:        "TLS Certificates",
			description: "Private TLS certificates found",
			patterns:    []string{"*.key", "*.pem", "*.pfx", "*.p12"},
		},
		{
			name:        "Git Credentials",
			description: "Git credentials found",
			patterns:    []string{".git-credentials", ".netrc"},
		},
	}

	var issues []config.ComplianceIssue

	for _, patternGroup := range patterns {
		var matches []string
		for file := range s.fileMap {
			for _, p := range patternGroup.patterns {
				if ok, _ := filepath.Match(p, filepath.Base(file)); ok {
					matches = append(matches, file)
				}
				if strings.Contains(file, p) && !strings.Contains(file, ".pub") {
					matches = append(matches, file)
				}
			}
		}

		if len(matches) > 0 {
			issues = append(issues, config.ComplianceIssue{
				RuleID:      "CIS-DI-0002",
				RuleName:    patternGroup.name,
				Severity:    config.SeverityCritical,
				Description: patternGroup.description,
				Evidence:    matches,
			})
		}
	}

	return issues
}

func (s *Scanner) checkSUIDFiles() []config.ComplianceIssue {
	suidFiles := []string{
		"/bin/ping", "/usr/bin/ping",
		"/bin/mount", "/usr/bin/mount",
		"/bin/umount", "/usr/bin/umount",
		"/usr/bin/su", "/bin/su",
		"/usr/bin/sudo",
		"/usr/bin/chsh", "/usr/bin/chfn",
		"/usr/bin/newgrp",
		"/usr/bin/gpasswd",
		"/usr/bin/passwd",
		"/usr/bin/crontab",
	}

	var found []string
	for _, f := range suidFiles {
		f = strings.TrimPrefix(f, "/")
		if _, ok := s.fileMap[f]; ok {
			found = append(found, f)
		}
	}

	if len(found) > 0 {
		return []config.ComplianceIssue{
			{
				RuleID:      "CIS-DI-0003",
				RuleName:    "SUID/SGID Files",
				Severity:    config.SeverityMedium,
				Description: "Files with SUID/SGID bits set may allow privilege escalation",
				Evidence:    found,
			},
		}
	}

	return nil
}

func (s *Scanner) checkUnwantedPackages() []config.ComplianceIssue {
	unwanted := map[string][]string{
		"Network Tools": {"curl", "wget", "netcat", "nc", "ncat", "net-tools", "iputils-ping", "telnet", "nmap", "tcpdump"},
		"Debug Tools":   {"gdb", "strace", "ltrace", "objdump", "binutils", "valgrind"},
		"Compilers":     {"gcc", "g++", "clang", "make", "cmake", "autoconf", "automake"},
		"Shells":        {"zsh", "ksh", "csh", "tcsh"},
	}

	var issues []config.ComplianceIssue

	for category, pkgNames := range unwanted {
		var found []string
		for _, pkg := range s.packages {
			for _, name := range pkgNames {
				if strings.Contains(strings.ToLower(pkg.Name), strings.ToLower(name)) {
					found = append(found, pkg.Name+"-"+pkg.Version)
				}
			}
		}

		if len(found) > 0 {
			issues = append(issues, config.ComplianceIssue{
				RuleID:      "CIS-DI-0004",
				RuleName:    "Unwanted " + category,
				Severity:    config.SeverityLow,
				Description: "Consider removing unnecessary " + strings.ToLower(category) + " to reduce attack surface",
				Evidence:    found,
			})
		}
	}

	return issues
}

func (s *Scanner) checkLatestTag() *config.ComplianceIssue {
	for _, hist := range s.history {
		if strings.Contains(hist, "FROM") && (strings.Contains(hist, ":latest") || !strings.Contains(hist, ":")) {
			return &config.ComplianceIssue{
				RuleID:      "CIS-DI-0005",
				RuleName:    "Latest Base Image",
				Severity:    config.SeverityMedium,
				Description: "Base image uses latest tag which can cause non-deterministic builds",
				Evidence:    []string{hist},
			}
		}
	}
	return nil
}
