package dockerfile

import (
	"bufio"
	"os"
	"strings"

	"imgscan/internal/config"
)

type Checker struct {
	path string
}

func NewChecker(path string) *Checker {
	return &Checker{
		path: path,
	}
}

func (c *Checker) Check() ([]config.DockerfileIssue, error) {
	if c.path == "" {
		return nil, nil
	}

	content, err := os.ReadFile(c.path)
	if err != nil {
		return nil, err
	}

	var issues []config.DockerfileIssue

	lines := strings.Split(string(content), "\n")

	if !checkMultiStageBuild(lines) {
		issues = append(issues, config.DockerfileIssue{
			RuleID:      "DF-BP-0001",
			RuleName:    "Multi-stage Build",
			Severity:    config.SeverityMedium,
			Description: "Consider using multi-stage builds to reduce image size and attack surface",
			Line:        0,
		})
	}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "FROM") {
			if strings.Contains(trimmed, ":latest") || !strings.Contains(trimmed, ":") {
				issues = append(issues, config.DockerfileIssue{
					RuleID:      "DF-BP-0002",
					RuleName:    "Fixed Base Image Version",
					Severity:    config.SeverityMedium,
					Description: "Base image should use a specific version tag, not 'latest' or no tag",
					Line:        lineNum,
				})
			}
		}

		if strings.HasPrefix(trimmed, "ADD") && (strings.Contains(trimmed, "http://") || strings.Contains(trimmed, "https://")) {
			issues = append(issues, config.DockerfileIssue{
				RuleID:      "DF-BP-0003",
				RuleName:    "Avoid ADD with Remote URL",
				Severity:    config.SeverityLow,
				Description: "Use RUN curl/wget instead of ADD for remote files to better control caching and verification",
				Line:        lineNum,
			})
		}
	}

	runCount := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "RUN") && !strings.HasPrefix(trimmed, "RUN --") {
			runCount++
		}
	}

	if runCount > 5 {
		issues = append(issues, config.DockerfileIssue{
			RuleID:      "DF-BP-0004",
			RuleName:    "Merge RUN Instructions",
			Severity:    config.SeverityLow,
			Description: "Consider merging multiple RUN instructions to reduce image layers",
			Line:        0,
		})
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "COPY") || strings.HasPrefix(trimmed, "ADD") {
			if !strings.Contains(trimmed, "--chown") && !strings.Contains(trimmed, "--from=") {
			}
		}
	}

	return issues, nil
}

func checkMultiStageBuild(lines []string) bool {
	fromCount := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "FROM") {
			fromCount++
		}
	}
	return fromCount > 2
}

func ParseDockerfile(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}
