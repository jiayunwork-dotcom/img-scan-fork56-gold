package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"

	"imgscan/internal/config"
)

type Reporter interface {
	Generate(result *config.ScanResult) error
}

type ConsoleReporter struct{}

type JSONReporter struct {
	OutputFile string
}

type SARIFReporter struct {
	OutputFile string
}

type HTMLReporter struct {
	OutputFile string
}

func NewReporter(format, outputFile string) Reporter {
	switch format {
	case "json":
		return &JSONReporter{OutputFile: outputFile}
	case "sarif":
		return &SARIFReporter{OutputFile: outputFile}
	case "html":
		return &HTMLReporter{OutputFile: outputFile}
	default:
		return &ConsoleReporter{}
	}
}

func (r *ConsoleReporter) Generate(result *config.ScanResult) error {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	fmt.Printf("\n%s\n", cyan("=== Image Security Scan Report ==="))
	fmt.Printf("Image: %s\n", result.ImageName)
	fmt.Printf("Scan Time: %s\n", result.ScanTime)
	fmt.Printf("\n%s\n", cyan("--- Scan Summary ---"))
	fmt.Printf("Total Layers: %d\n", len(result.Layers))
	fmt.Printf("Total Packages: %d\n", len(result.Packages))

	summaryColor := white
	if result.TotalCritical > 0 || result.TotalHigh > 0 {
		summaryColor = red
	} else if result.TotalMedium > 0 {
		summaryColor = yellow
	}
	fmt.Printf("%s", summaryColor(fmt.Sprintf("Vulnerabilities: %d Critical, %d High, %d Medium, %d Low\n",
		result.TotalCritical, result.TotalHigh, result.TotalMedium, result.TotalLow)))

	if len(result.Vulnerabilities) > 0 {
		fmt.Printf("\n%s\n", cyan("--- Vulnerabilities ---"))
		sortVulnerabilities(result.Vulnerabilities)

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Severity", "CVE", "Package", "Version", "Fixed", "Layer"})
		table.SetAutoWrapText(false)

		for _, vuln := range result.Vulnerabilities {
			severityColor := getSeverityColor(vuln.Severity)
			table.Append([]string{
				severityColor(string(vuln.Severity)),
				vuln.CVE,
				vuln.PackageName,
				vuln.PackageVersion,
				vuln.FixedVersion,
				fmt.Sprintf("%d", vuln.LayerIdx),
			})
		}
		table.Render()
	}

	if len(result.Compliance) > 0 {
		fmt.Printf("\n%s\n", cyan("--- Compliance Issues ---"))
		for _, issue := range result.Compliance {
			sevColor := getSeverityColor(issue.Severity)
			fmt.Printf("[%s] %s: %s\n", sevColor(string(issue.Severity)), issue.RuleName, issue.Description)
			if len(issue.Evidence) > 0 {
				fmt.Printf("  Evidence: %s\n", strings.Join(issue.Evidence, ", "))
			}
		}
	}

	if len(result.Dockerfile) > 0 {
		fmt.Printf("\n%s\n", cyan("--- Dockerfile Best Practices ---"))
		for _, issue := range result.Dockerfile {
			sevColor := getSeverityColor(issue.Severity)
			lineInfo := ""
			if issue.Line > 0 {
				lineInfo = fmt.Sprintf(" (line %d)", issue.Line)
			}
			fmt.Printf("[%s] %s%s: %s\n", sevColor(string(issue.Severity)), issue.RuleName, lineInfo, issue.Description)
		}
	}

	fmt.Printf("\n")
	return nil
}

func getSeverityColor(severity config.Severity) func(a ...interface{}) string {
	switch severity {
	case config.SeverityCritical:
		return color.New(color.FgRed, color.Bold).SprintFunc()
	case config.SeverityHigh:
		return color.New(color.FgHiRed).SprintFunc()
	case config.SeverityMedium:
		return color.New(color.FgYellow).SprintFunc()
	default:
		return color.New(color.FgWhite).SprintFunc()
	}
}

func sortVulnerabilities(vulns []config.Vulnerability) {
	severityOrder := map[config.Severity]int{
		config.SeverityCritical: 0,
		config.SeverityHigh:     1,
		config.SeverityMedium:   2,
		config.SeverityLow:      3,
	}
	sort.Slice(vulns, func(i, j int) bool {
		if severityOrder[vulns[i].Severity] != severityOrder[vulns[j].Severity] {
			return severityOrder[vulns[i].Severity] < severityOrder[vulns[j].Severity]
		}
		return vulns[i].CVSS > vulns[j].CVSS
	})
}

func (r *JSONReporter) Generate(result *config.ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	if r.OutputFile != "" {
		return os.WriteFile(r.OutputFile, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

type SARIFReport struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool    `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	ShortDescription Description `json:"shortDescription"`
	FullDescription  Description `json:"fullDescription"`
	Help           Description `json:"help"`
	Properties     RuleProperties `json:"properties"`
}

type Description struct {
	Text string `json:"text"`
}

type RuleProperties struct {
	Severity string `json:"severity"`
}

type Result struct {
	RuleID     string      `json:"ruleId"`
	Level      string      `json:"level"`
	Message    Description `json:"message"`
	Locations  []Location  `json:"locations"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
}

func (r *SARIFReporter) Generate(result *config.ScanResult) error {
	var rules []Rule
	var results []Result

	for _, vuln := range result.Vulnerabilities {
		ruleID := fmt.Sprintf("VULN-%s", vuln.CVE)
		rules = append(rules, Rule{
			ID:   ruleID,
			Name: vuln.Title,
			ShortDescription: Description{Text: vuln.Description},
			FullDescription:  Description{Text: fmt.Sprintf("Package: %s %s", vuln.PackageName, vuln.PackageVersion)},
			Help: Description{Text: fmt.Sprintf("Fix version: %s", vuln.FixedVersion)},
			Properties: RuleProperties{Severity: string(vuln.Severity)},
		})

		results = append(results, Result{
			RuleID:  ruleID,
			Level:   sarifLevel(vuln.Severity),
			Message: Description{Text: vuln.Description},
			Locations: []Location{{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: result.ImageName},
					Region:           Region{StartLine: vuln.LayerIdx + 1},
				},
			}},
		})
	}

	for _, issue := range result.Compliance {
		rules = append(rules, Rule{
			ID:   issue.RuleID,
			Name: issue.RuleName,
			ShortDescription: Description{Text: issue.Description},
			FullDescription:  Description{Text: strings.Join(issue.Evidence, ", ")},
			Help: Description{Text: "Review and remediate compliance issue"},
			Properties: RuleProperties{Severity: string(issue.Severity)},
		})

		results = append(results, Result{
			RuleID:  issue.RuleID,
			Level:   sarifLevel(issue.Severity),
			Message: Description{Text: issue.Description},
			Locations: []Location{{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: result.ImageName},
				},
			}},
		})
	}

	sarif := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{{
			Tool: Tool{
				Driver: Driver{
					Name:           "imgscan",
					Version:        "1.0.0",
					InformationURI: "https://github.com/imgscan/imgscan",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}

	if r.OutputFile != "" {
		return os.WriteFile(r.OutputFile, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func sarifLevel(severity config.Severity) string {
	switch severity {
	case config.SeverityCritical, config.SeverityHigh:
		return "error"
	case config.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Image Security Scan Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; margin-bottom: 20px; }
        .summary { background: #16213e; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }
        .stat { background: #0f3460; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .critical { color: #ff4757; }
        .high { color: #ff6b35; }
        .medium { color: #ffd93d; }
        .low { color: #6bcb77; }
        .search-box { width: 100%; padding: 12px; margin-bottom: 20px; background: #0f3460; border: 1px solid #00d4ff; border-radius: 8px; color: #eee; font-size: 16px; }
        .panel { background: #16213e; border-radius: 10px; margin-bottom: 15px; overflow: hidden; }
        .panel-header { padding: 15px; background: #0f3460; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .panel-header:hover { background: #1a4a7a; }
        .panel-content { padding: 15px; display: none; }
        .panel-content.open { display: block; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #0f3460; }
        th { background: #0f3460; color: #00d4ff; }
        tr:hover { background: #0f3460; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Image Security Scan Report</h1>
        
        <div class="summary">
            <h2>{{.ImageName}}</h2>
            <p>Scan Time: {{.ScanTime}}</p>
            <div class="summary-grid">
                <div class="stat">
                    <div class="stat-value">{{len .Layers}}</div>
                    <div>Layers</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{{len .Packages}}</div>
                    <div>Packages</div>
                </div>
                <div class="stat">
                    <div class="stat-value critical">{{.TotalCritical}}</div>
                    <div>Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-value high">{{.TotalHigh}}</div>
                    <div>High</div>
                </div>
                <div class="stat">
                    <div class="stat-value medium">{{.TotalMedium}}</div>
                    <div>Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-value low">{{.TotalLow}}</div>
                    <div>Low</div>
                </div>
            </div>
        </div>

        <input type="text" class="search-box" placeholder="🔍 Search vulnerabilities..." id="searchInput">

        {{if .Vulnerabilities}}
        <div class="panel">
            <div class="panel-header" onclick="togglePanel(this)">
                <span>⚠️ Vulnerabilities ({{len .Vulnerabilities}})</span>
                <span>▼</span>
            </div>
            <div class="panel-content open">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>CVE</th>
                            <th>Package</th>
                            <th>Version</th>
                            <th>Fixed</th>
                            <th>Layer</th>
                        </tr>
                    </thead>
                    <tbody id="vulnTable">
                        {{range .Vulnerabilities}}
                        <tr class="vuln-row" data-search="{{.CVE}} {{.PackageName}} {{.Title}}">
                            <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
                            <td>{{.CVE}}</td>
                            <td>{{.PackageName}}</td>
                            <td>{{.PackageVersion}}</td>
                            <td>{{.FixedVersion}}</td>
                            <td>{{.LayerIdx}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>
        {{end}}

        {{if .Compliance}}
        <div class="panel">
            <div class="panel-header" onclick="togglePanel(this)">
                <span>📋 Compliance Issues ({{len .Compliance}})</span>
                <span>▼</span>
            </div>
            <div class="panel-content">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Rule</th>
                            <th>Description</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Compliance}}
                        <tr>
                            <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
                            <td>{{.RuleName}}</td>
                            <td>{{.Description}}</td>
                            <td>{{range .Evidence}}{{.}}, {{end}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>
        {{end}}

        {{if .Dockerfile}}
        <div class="panel">
            <div class="panel-header" onclick="togglePanel(this)">
                <span>🐳 Dockerfile Best Practices ({{len .Dockerfile}})</span>
                <span>▼</span>
            </div>
            <div class="panel-content">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Rule</th>
                            <th>Line</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Dockerfile}}
                        <tr>
                            <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
                            <td>{{.RuleName}}</td>
                            <td>{{.Line}}</td>
                            <td>{{.Description}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>
        {{end}}
    </div>

    <script>
        function togglePanel(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('open');
            const arrow = header.querySelector('span:last-child');
            arrow.textContent = content.classList.contains('open') ? '▼' : '▶';
        }

        document.getElementById('searchInput').addEventListener('input', function(e) {
            const search = e.target.value.toLowerCase();
            document.querySelectorAll('.vuln-row').forEach(row => {
                const text = row.dataset.search.toLowerCase();
                row.style.display = text.includes(search) ? '' : 'none';
            });
        });
    </script>
</body>
</html>
`

func (r *HTMLReporter) Generate(result *config.ScanResult) error {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	var output *os.File
	if r.OutputFile != "" {
		output, err = os.Create(r.OutputFile)
		if err != nil {
			return err
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	return tmpl.Execute(output, result)
}
