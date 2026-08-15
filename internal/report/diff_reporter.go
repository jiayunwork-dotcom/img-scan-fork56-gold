package report

import (
	"encoding/json"
	"fmt"
	"os"
	"text/template"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"

	"imgscan/internal/config"
)

type DiffReporter interface {
	Generate(diff *config.DiffResult) error
}

type ConsoleDiffReporter struct{}

type JSONDiffReporter struct {
	OutputFile string
}

type HTMLDiffReporter struct {
	OutputFile string
}

func NewDiffReporter(format, outputFile string) DiffReporter {
	switch format {
	case "json":
		return &JSONDiffReporter{OutputFile: outputFile}
	case "html":
		return &HTMLDiffReporter{OutputFile: outputFile}
	default:
		return &ConsoleDiffReporter{}
	}
}

func (r *ConsoleDiffReporter) Generate(diff *config.DiffResult) error {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	fmt.Printf("\n%s\n", cyan("=== Image Diff Report ==="))
	fmt.Printf("Old Image: %s\n", diff.OldImage)
	fmt.Printf("New Image: %s\n", diff.NewImage)
	fmt.Printf("Scan Time: %s\n", diff.ScanTime)

	renderVulnerabilityDiff(diff, cyan, green, red, yellow, white)
	renderPackageDiff(diff, cyan, green, red, yellow, white)
	renderLayerDiff(diff, cyan, green, red, yellow, white)
	renderComplianceDiff(diff, cyan, green, red, yellow, white)

	fmt.Printf("\n")
	return nil
}

func renderVulnerabilityDiff(diff *config.DiffResult, cyan, green, red, yellow, white func(a ...interface{}) string) {
	vd := diff.VulnerabilityDiff
	totalAdded := len(vd.Added)
	totalRemoved := len(vd.Removed)
	totalUnchanged := len(vd.Unchanged)

	fmt.Printf("\n%s\n", cyan("--- Vulnerability Changes ---"))
	fmt.Printf("%s %s  %s %s  %s %s\n",
		green(fmt.Sprintf("+%d Fixed", totalRemoved)),
		"",
		red(fmt.Sprintf("-%d New", totalAdded)),
		"",
		white(fmt.Sprintf(" %d Unchanged", totalUnchanged)),
		"",
	)

	if totalAdded > 0 || totalRemoved > 0 {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"", "Severity", "CVE", "Package", "Version", "Fixed"})
		table.SetAutoWrapText(false)

		for _, v := range vd.Added {
			sevColor := getSeverityColor(v.Severity)
			table.Append([]string{
				red("+"),
				sevColor(string(v.Severity)),
				v.CVE,
				v.PackageName,
				v.PackageVersion,
				v.FixedVersion,
			})
		}

		for _, v := range vd.Removed {
			sevColor := getSeverityColor(v.Severity)
			table.Append([]string{
				green("-"),
				sevColor(string(v.Severity)),
				v.CVE,
				v.PackageName,
				v.PackageVersion,
				v.FixedVersion,
			})
		}

		for _, v := range vd.Unchanged {
			sevColor := getSeverityColor(v.Severity)
			table.Append([]string{
				" ",
				sevColor(string(v.Severity)),
				v.CVE,
				v.PackageName,
				v.PackageVersion,
				v.FixedVersion,
			})
		}

		table.Render()
	}
}

func renderPackageDiff(diff *config.DiffResult, cyan, green, red, yellow, white func(a ...interface{}) string) {
	pd := diff.PackageDiff
	totalAdded := len(pd.Added)
	totalRemoved := len(pd.Removed)
	totalUpgraded := len(pd.Upgraded)
	totalDowngraded := len(pd.Downgraded)
	totalUnchanged := len(pd.Unchanged)

	fmt.Printf("\n%s\n", cyan("--- Package Changes ---"))
	fmt.Printf("%s %s  %s %s  %s %s  %s %s  %s %s\n",
		green(fmt.Sprintf("+%d Added", totalAdded)),
		"",
		red(fmt.Sprintf("-%d Removed", totalRemoved)),
		"",
		yellow(fmt.Sprintf("↑%d Upgraded", totalUpgraded)),
		"",
		yellow(fmt.Sprintf("↓%d Downgraded", totalDowngraded)),
		"",
		white(fmt.Sprintf(" %d Unchanged", totalUnchanged)),
		"",
	)

	hasChanges := totalAdded > 0 || totalRemoved > 0 || totalUpgraded > 0 || totalDowngraded > 0
	if hasChanges {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"", "Type", "Package", "Old Version", "New Version"})
		table.SetAutoWrapText(false)

		for _, p := range pd.Added {
			table.Append([]string{
				green("+"),
				string(p.Type),
				p.Name,
				"-",
				p.Version,
			})
		}

		for _, p := range pd.Removed {
			table.Append([]string{
				red("-"),
				string(p.Type),
				p.Name,
				p.Version,
				"-",
			})
		}

		for _, c := range pd.Upgraded {
			table.Append([]string{
				yellow("↑"),
				string(c.Package.Type),
				c.Package.Name,
				c.OldVersion,
				green(c.NewVersion),
			})
		}

		for _, c := range pd.Downgraded {
			table.Append([]string{
				yellow("↓"),
				string(c.Package.Type),
				c.Package.Name,
				c.OldVersion,
				red(c.NewVersion),
			})
		}

		table.Render()
	}
}

func renderLayerDiff(diff *config.DiffResult, cyan, green, red, yellow, white func(a ...interface{}) string) {
	ld := diff.LayerDiff

	fmt.Printf("\n%s\n", cyan("--- Layer Structure Changes ---"))
	fmt.Printf("Layers: %d → %d (change: %+d)\n",
		ld.OldLayerCount, ld.NewLayerCount, ld.NewLayerCount-ld.OldLayerCount)

	hasChanges := false
	for _, lc := range ld.LayerChanges {
		if lc.ChangeType != "unchanged" {
			hasChanges = true
			break
		}
	}

	if hasChanges {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"", "Layer", "Old Files", "New Files", "Delta"})

		for _, lc := range ld.LayerChanges {
			delta := lc.NewFileCount - lc.OldFileCount
			deltaStr := fmt.Sprintf("%+d", delta)

			prefix := " "
			deltaColored := white(deltaStr)
			if delta > 0 {
				deltaColored = green(deltaStr)
			} else if delta < 0 {
				deltaColored = red(deltaStr)
			}

			switch lc.ChangeType {
			case "added":
				prefix = green("+")
			case "removed":
				prefix = red("-")
			case "modified":
				prefix = yellow("~")
			}

			table.Append([]string{
				prefix,
				fmt.Sprintf("Layer %d", lc.Index),
				fmt.Sprintf("%d", lc.OldFileCount),
				fmt.Sprintf("%d", lc.NewFileCount),
				deltaColored,
			})
		}

		table.Render()
	}
}

func renderComplianceDiff(diff *config.DiffResult, cyan, green, red, yellow, white func(a ...interface{}) string) {
	cd := diff.ComplianceDiff
	totalAdded := len(cd.Added)
	totalRemoved := len(cd.Removed)
	totalUnchanged := len(cd.Unchanged)

	fmt.Printf("\n%s\n", cyan("--- Compliance Changes ---"))
	fmt.Printf("%s %s  %s %s  %s %s\n",
		green(fmt.Sprintf("+%d Resolved", totalRemoved)),
		"",
		red(fmt.Sprintf("-%d New", totalAdded)),
		"",
		white(fmt.Sprintf(" %d Unchanged", totalUnchanged)),
		"",
	)

	if totalAdded > 0 || totalRemoved > 0 {
		for _, issue := range cd.Added {
			sevColor := getSeverityColor(issue.Severity)
			fmt.Printf("%s [%s] %s: %s\n", red("+"), sevColor(string(issue.Severity)), issue.RuleName, issue.Description)
		}

		for _, issue := range cd.Removed {
			sevColor := getSeverityColor(issue.Severity)
			fmt.Printf("%s [%s] %s: %s\n", green("-"), sevColor(string(issue.Severity)), issue.RuleName, issue.Description)
		}
	}
}

func (r *JSONDiffReporter) Generate(diff *config.DiffResult) error {
	data, err := json.MarshalIndent(diff, "", "  ")
	if err != nil {
		return err
	}

	if r.OutputFile != "" {
		return os.WriteFile(r.OutputFile, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

const htmlDiffTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Image Diff Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #00d4ff; margin-bottom: 20px; }
        .diff-header { background: #16213e; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .diff-images { display: flex; gap: 20px; margin-top: 10px; }
        .diff-image-box { flex: 1; background: #0f3460; padding: 15px; border-radius: 8px; }
        .diff-image-box.old { border-left: 4px solid #ff4757; }
        .diff-image-box.new { border-left: 4px solid #6bcb77; }
        .diff-image-label { font-size: 12px; color: #888; margin-bottom: 5px; }
        .diff-image-name { font-size: 16px; font-weight: bold; word-break: break-all; }
        .tabs { display: flex; gap: 2px; margin-bottom: 0; }
        .tab { padding: 12px 24px; background: #0f3460; cursor: pointer; border-radius: 8px 8px 0 0; font-weight: bold; }
        .tab.active { background: #16213e; color: #00d4ff; }
        .tab-content { display: none; background: #16213e; border-radius: 0 8px 8px 8px; padding: 20px; margin-bottom: 20px; }
        .tab-content.active { display: block; }
        .split-view { display: flex; gap: 20px; }
        .split-column { flex: 1; }
        .split-column h3 { color: #00d4ff; margin-bottom: 10px; font-size: 14px; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .Critical { background: #ff4757; color: white; }
        .High { background: #ff6b35; color: white; }
        .Medium { background: #ffd93d; color: #1a1a2e; }
        .Low { background: #6bcb77; color: white; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 15px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #0f3460; font-size: 13px; }
        th { background: #0f3460; color: #00d4ff; }
        tr.added { background: rgba(107, 203, 119, 0.1); }
        tr.removed { background: rgba(255, 71, 87, 0.1); }
        tr.unchanged td { color: #888; }
        .delta-pos { color: #6bcb77; }
        .delta-neg { color: #ff4757; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .card { background: #0f3460; padding: 15px; border-radius: 8px; text-align: center; }
        .card-value { font-size: 28px; font-weight: bold; }
        .card-label { font-size: 12px; color: #888; margin-top: 5px; }
        .card.added .card-value { color: #6bcb77; }
        .card.removed .card-value { color: #ff4757; }
        .card.unchanged .card-value { color: #888; }
        .card.upgraded .card-value { color: #ffd93d; }
        .card.downgraded .card-value { color: #ff9f43; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Image Diff Report</h1>

        <div class="diff-header">
            <div class="diff-images">
                <div class="diff-image-box old">
                    <div class="diff-image-label">OLD IMAGE</div>
                    <div class="diff-image-name">{{.OldImage}}</div>
                </div>
                <div class="diff-image-box new">
                    <div class="diff-image-label">NEW IMAGE</div>
                    <div class="diff-image-name">{{.NewImage}}</div>
                </div>
            </div>
        </div>

        <div class="summary-cards">
            <div class="card added">
                <div class="card-value">{{len .VulnerabilityDiff.Added}}</div>
                <div class="card-label">New Vulnerabilities</div>
            </div>
            <div class="card removed">
                <div class="card-value">{{len .VulnerabilityDiff.Removed}}</div>
                <div class="card-label">Fixed Vulnerabilities</div>
            </div>
            <div class="card unchanged">
                <div class="card-value">{{len .VulnerabilityDiff.Unchanged}}</div>
                <div class="card-label">Unchanged Vulns</div>
            </div>
            <div class="card added">
                <div class="card-value">{{len .PackageDiff.Added}}</div>
                <div class="card-label">Added Packages</div>
            </div>
            <div class="card removed">
                <div class="card-value">{{len .PackageDiff.Removed}}</div>
                <div class="card-label">Removed Packages</div>
            </div>
            <div class="card upgraded">
                <div class="card-value">{{len .PackageDiff.Upgraded}}</div>
                <div class="card-label">Upgraded Packages</div>
            </div>
            <div class="card downgraded">
                <div class="card-value">{{len .PackageDiff.Downgraded}}</div>
                <div class="card-label">Downgraded Packages</div>
            </div>
            <div class="card added">
                <div class="card-value">{{len .ComplianceDiff.Added}}</div>
                <div class="card-label">New Compliance Issues</div>
            </div>
            <div class="card removed">
                <div class="card-value">{{len .ComplianceDiff.Removed}}</div>
                <div class="card-label">Resolved Compliance</div>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="switchTab(this, 'vuln')">⚠️ Vulnerabilities</div>
            <div class="tab" onclick="switchTab(this, 'packages')">📦 Packages</div>
            <div class="tab" onclick="switchTab(this, 'layers')">🗂 Layers</div>
            <div class="tab" onclick="switchTab(this, 'compliance')">📋 Compliance</div>
        </div>

        <div id="vuln" class="tab-content active">
            <div class="split-view">
                <div class="split-column">
                    <h3>New Vulnerabilities (in new image only)</h3>
                    <table>
                        <thead>
                            <tr><th>Severity</th><th>CVE</th><th>Package</th><th>Version</th><th>Fixed</th></tr>
                        </thead>
                        <tbody>
                            {{range .VulnerabilityDiff.Added}}
                            <tr class="added">
                                <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
                                <td>{{.CVE}}</td>
                                <td>{{.PackageName}}</td>
                                <td>{{.PackageVersion}}</td>
                                <td>{{.FixedVersion}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                <div class="split-column">
                    <h3>Fixed Vulnerabilities (in old image only)</h3>
                    <table>
                        <thead>
                            <tr><th>Severity</th><th>CVE</th><th>Package</th><th>Version</th><th>Fixed</th></tr>
                        </thead>
                        <tbody>
                            {{range .VulnerabilityDiff.Removed}}
                            <tr class="removed">
                                <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
                                <td>{{.CVE}}</td>
                                <td>{{.PackageName}}</td>
                                <td>{{.PackageVersion}}</td>
                                <td>{{.FixedVersion}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
            {{if .VulnerabilityDiff.Unchanged}}
            <h3 style="color: #888; margin-top: 20px; font-size: 14px;">Unchanged Vulnerabilities (present in both)</h3>
            <table>
                <thead>
                    <tr><th>Severity</th><th>CVE</th><th>Package</th><th>Version</th><th>Fixed</th></tr>
                </thead>
                <tbody>
                    {{range .VulnerabilityDiff.Unchanged}}
                    <tr class="unchanged">
                        <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
                        <td>{{.CVE}}</td>
                        <td>{{.PackageName}}</td>
                        <td>{{.PackageVersion}}</td>
                        <td>{{.FixedVersion}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{end}}
        </div>

        <div id="packages" class="tab-content">
            <div class="split-view">
                <div class="split-column">
                    <h3>Added Packages</h3>
                    <table>
                        <thead>
                            <tr><th>Type</th><th>Package</th><th>Version</th></tr>
                        </thead>
                        <tbody>
                            {{range .PackageDiff.Added}}
                            <tr class="added">
                                <td>{{.Type}}</td>
                                <td>{{.Name}}</td>
                                <td>{{.Version}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                    <h3>Removed Packages</h3>
                    <table>
                        <thead>
                            <tr><th>Type</th><th>Package</th><th>Version</th></tr>
                        </thead>
                        <tbody>
                            {{range .PackageDiff.Removed}}
                            <tr class="removed">
                                <td>{{.Type}}</td>
                                <td>{{.Name}}</td>
                                <td>{{.Version}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                <div class="split-column">
                    <h3>Upgraded Packages</h3>
                    <table>
                        <thead>
                            <tr><th>Type</th><th>Package</th><th>Old</th><th>New</th></tr>
                        </thead>
                        <tbody>
                            {{range .PackageDiff.Upgraded}}
                            <tr class="added">
                                <td>{{.Package.Type}}</td>
                                <td>{{.Package.Name}}</td>
                                <td>{{.OldVersion}}</td>
                                <td class="delta-pos">{{.NewVersion}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                    <h3>Downgraded Packages</h3>
                    <table>
                        <thead>
                            <tr><th>Type</th><th>Package</th><th>Old</th><th>New</th></tr>
                        </thead>
                        <tbody>
                            {{range .PackageDiff.Downgraded}}
                            <tr class="removed">
                                <td>{{.Package.Type}}</td>
                                <td>{{.Package.Name}}</td>
                                <td>{{.OldVersion}}</td>
                                <td class="delta-neg">{{.NewVersion}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="layers" class="tab-content">
            <div class="split-view">
                <div class="split-column">
                    <h3>Layer Comparison</h3>
                    <table>
                        <thead>
                            <tr><th>Layer</th><th>Old Files</th><th>New Files</th><th>Delta</th><th>Change</th></tr>
                        </thead>
                        <tbody>
                            {{range .LayerDiff.LayerChanges}}
                            <tr class="{{if eq .ChangeType "added"}}added{{else if eq .ChangeType "removed"}}removed{{end}}">
                                <td>Layer {{.Index}}</td>
                                <td>{{.OldFileCount}}</td>
                                <td>{{.NewFileCount}}</td>
                                <td class="{{if gt (sub .NewFileCount .OldFileCount) 0}}delta-pos{{else if lt (sub .NewFileCount .OldFileCount) 0}}delta-neg{{end}}">{{delta .NewFileCount .OldFileCount}}</td>
                                <td>{{.ChangeType}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="compliance" class="tab-content">
            <div class="split-view">
                <div class="split-column">
                    <h3>New Compliance Issues</h3>
                    <table>
                        <thead>
                            <tr><th>Severity</th><th>Rule</th><th>Description</th></tr>
                        </thead>
                        <tbody>
                            {{range .ComplianceDiff.Added}}
                            <tr class="added">
                                <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
                                <td>{{.RuleName}}</td>
                                <td>{{.Description}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                <div class="split-column">
                    <h3>Resolved Compliance Issues</h3>
                    <table>
                        <thead>
                            <tr><th>Severity</th><th>Rule</th><th>Description</th></tr>
                        </thead>
                        <tbody>
                            {{range .ComplianceDiff.Removed}}
                            <tr class="removed">
                                <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
                                <td>{{.RuleName}}</td>
                                <td>{{.Description}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
            {{if .ComplianceDiff.Unchanged}}
            <h3 style="color: #888; margin-top: 20px; font-size: 14px;">Unchanged Compliance Issues</h3>
            <table>
                <thead>
                    <tr><th>Severity</th><th>Rule</th><th>Description</th></tr>
                </thead>
                <tbody>
                    {{range .ComplianceDiff.Unchanged}}
                    <tr class="unchanged">
                        <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
                        <td>{{.RuleName}}</td>
                        <td>{{.Description}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{end}}
        </div>
    </div>

    <script>
        function switchTab(el, tabId) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            el.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }
    </script>
</body>
</html>
`

type htmlDiffTemplateData struct {
	*config.DiffResult
}

func (t htmlDiffTemplateData) Delta(newCount, oldCount int) string {
	delta := newCount - oldCount
	return fmt.Sprintf("%+d", delta)
}

func (t htmlDiffTemplateData) Sub(a, b int) int {
	return a - b
}

func (r *HTMLDiffReporter) Generate(diff *config.DiffResult) error {
	funcMap := template.FuncMap{
		"delta": func(newCount, oldCount int) string {
			return fmt.Sprintf("%+d", newCount-oldCount)
		},
		"sub": func(a, b int) int {
			return a - b
		},
	}

	tmpl, err := template.New("diff-report").Funcs(funcMap).Parse(htmlDiffTemplate)
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

	return tmpl.Execute(output, diff)
}
