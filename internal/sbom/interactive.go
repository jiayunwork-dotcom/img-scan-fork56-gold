package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	styleRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	styleGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	styleCyan   = lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleHeader = lipgloss.NewStyle().Foreground(lipgloss.Color("213")).Bold(true)
	styleCursor = lipgloss.NewStyle().Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230"))
	styleSearch = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
)

type treeNode struct {
	Pkg      *SBOMPackage
	Children []*treeNode
	Expanded bool
	Depth    int
	IsLast   bool
}

type viewMode int

const (
	modeTree viewMode = iota
	modeSearch
	modeImpact
	modeUpgrade
)

type interactiveModel struct {
	doc        *SBOMDocument
	roots      []*treeNode
	flatNodes  []*treeNode
	cursor     int
	mode       viewMode
	searchInput textinput.Model
	searchResults []*treeNode
	searchCursor  int
	impactPkg  *SBOMPackage
	upgradePkg *SBOMPackage
	impactInfo *ImpactInfo
	upgradeInfo *UpgradeInfo
	errMsg     string
	quit       bool
	reverseDeps map[string][]string
	allNodes   map[string]*treeNode
}

type ImpactInfo struct {
	ReverseDeps []string
	AffectedCount int
	RemoveImpact  []string
}

type UpgradeInfo struct {
	CurrentVersion string
	AvailableVersions []FixedVersionInfo
}

type FixedVersionInfo struct {
	Version   string
	FixedCVEs []string
}

func RunInteractive(doc *SBOMDocument) error {
	roots := buildTree(doc)
	reverseDeps := buildReverseDeps(doc)

	ti := textinput.New()
	ti.Placeholder = "输入包名搜索..."
	ti.CharLimit = 50

	model := interactiveModel{
		doc:         doc,
		roots:       roots,
		mode:        modeTree,
		searchInput: ti,
		reverseDeps: reverseDeps,
		allNodes:    make(map[string]*treeNode),
	}

	collectAllNodes(roots, model.allNodes)
	model.flatNodes = flattenVisible(roots)

	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func buildTree(doc *SBOMDocument) []*treeNode {
	pkgMap := make(map[string]*SBOMPackage)
	for i := range doc.Packages {
		pkgMap[doc.Packages[i].ID] = &doc.Packages[i]
	}

	childMap := make(map[string][]string)
	for _, rel := range doc.Relationships {
		if rel.RelationshipType == "DEPENDS_ON" {
			childMap[rel.SourceID] = append(childMap[rel.SourceID], rel.TargetID)
		}
	}

	directPkgs := make(map[string]bool)
	for _, rel := range doc.Relationships {
		if rel.RelationshipType == "DESCRIBES" && rel.SourceID == "DOCUMENT" {
			directPkgs[rel.TargetID] = true
		}
	}

	for _, pkg := range doc.Packages {
		if pkg.Provenance.IsDirect {
			directPkgs[pkg.ID] = true
		}
	}

	var roots []*treeNode
	seen := make(map[string]bool)

	var directPkgsSorted []*SBOMPackage
	for i := range doc.Packages {
		if directPkgs[doc.Packages[i].ID] {
			directPkgsSorted = append(directPkgsSorted, &doc.Packages[i])
		}
	}
	sort.Slice(directPkgsSorted, func(i, j int) bool {
		return directPkgsSorted[i].Name < directPkgsSorted[j].Name
	})

	for idx, pkg := range directPkgsSorted {
		if seen[pkg.ID] {
			continue
		}
		seen[pkg.ID] = true
		node := buildTreeNode(pkg, childMap, pkgMap, seen, 0, idx == len(directPkgsSorted)-1)
		roots = append(roots, node)
	}

	if len(roots) == 0 {
		sortedPkgs := make([]*SBOMPackage, len(doc.Packages))
		for i := range doc.Packages {
			sortedPkgs[i] = &doc.Packages[i]
		}
		sort.Slice(sortedPkgs, func(i, j int) bool {
			return sortedPkgs[i].Name < sortedPkgs[j].Name
		})
		for idx, pkg := range sortedPkgs {
			node := &treeNode{
				Pkg:    pkg,
				Depth:  0,
				IsLast: idx == len(sortedPkgs)-1,
			}
			roots = append(roots, node)
		}
	}

	return roots
}

func buildTreeNode(pkg *SBOMPackage, childMap map[string][]string, pkgMap map[string]*SBOMPackage, seen map[string]bool, depth int, isLast bool) *treeNode {
	node := &treeNode{
		Pkg:    pkg,
		Depth:  depth,
		IsLast: isLast,
	}

	childIDs := childMap[pkg.ID]
	for i, childID := range childIDs {
		childPkg, ok := pkgMap[childID]
		if !ok || seen[childID] {
			continue
		}
		seen[childID] = true
		childNode := buildTreeNode(childPkg, childMap, pkgMap, seen, depth+1, i == len(childIDs)-1)
		node.Children = append(node.Children, childNode)
	}

	return node
}

func buildReverseDeps(doc *SBOMDocument) map[string][]string {
	reverseDeps := make(map[string][]string)
	for _, rel := range doc.Relationships {
		if rel.RelationshipType == "DEPENDS_ON" {
			reverseDeps[rel.TargetID] = append(reverseDeps[rel.TargetID], rel.SourceID)
		}
	}
	return reverseDeps
}

func collectAllNodes(roots []*treeNode, allNodes map[string]*treeNode) {
	for _, root := range roots {
		allNodes[root.Pkg.ID] = root
		collectAllNodes(root.Children, allNodes)
	}
}

func flattenVisible(roots []*treeNode) []*treeNode {
	var result []*treeNode
	for _, root := range roots {
		result = append(result, root)
		if root.Expanded {
			result = append(result, flattenVisible(root.Children)...)
		}
	}
	return result
}

func (m interactiveModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m interactiveModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			m.quit = true
			return m, tea.Quit
		}
	}

	switch m.mode {
	case modeTree:
		return m.updateTree(msg)
	case modeSearch:
		return m.updateSearch(msg)
	case modeImpact:
		return m.updateImpact(msg)
	case modeUpgrade:
		return m.updateUpgrade(msg)
	}
	return m, nil
}

func (m interactiveModel) updateTree(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q":
			m.quit = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.flatNodes)-1 {
				m.cursor++
			}
		case "enter":
			if m.cursor >= 0 && m.cursor < len(m.flatNodes) {
				node := m.flatNodes[m.cursor]
				node.Expanded = !node.Expanded
				m.flatNodes = flattenVisible(m.roots)
				if m.cursor >= len(m.flatNodes) {
					m.cursor = len(m.flatNodes) - 1
				}
			}
		case "/":
			m.mode = modeSearch
			m.searchInput.Focus()
			return m, textinput.Blink
		case "d":
			if m.cursor >= 0 && m.cursor < len(m.flatNodes) {
				m.impactPkg = m.flatNodes[m.cursor].Pkg
				m.impactInfo = m.computeImpact(m.impactPkg)
				m.mode = modeImpact
			}
		case "u":
			if m.cursor >= 0 && m.cursor < len(m.flatNodes) {
				m.upgradePkg = m.flatNodes[m.cursor].Pkg
				m.upgradeInfo = m.computeUpgrade(m.upgradePkg)
				m.mode = modeUpgrade
			}
		case "e":
			if m.cursor >= 0 && m.cursor < len(m.flatNodes) {
				m.exportSubtree(m.flatNodes[m.cursor])
			}
		}
	}
	return m, nil
}

func (m interactiveModel) updateSearch(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.mode = modeTree
			m.searchInput.SetValue("")
			m.searchResults = nil
			return m, nil
		case "enter":
			if len(m.searchResults) > 0 && m.searchCursor < len(m.searchResults) {
				target := m.searchResults[m.searchCursor]
				m.expandToNode(target)
				m.flatNodes = flattenVisible(m.roots)
				for i, n := range m.flatNodes {
					if n == target {
						m.cursor = i
						break
					}
				}
			}
			m.mode = modeTree
			m.searchInput.SetValue("")
			m.searchResults = nil
			return m, nil
		case "up", "k":
			if m.searchCursor > 0 {
				m.searchCursor--
			}
		case "down", "j":
			if m.searchCursor < len(m.searchResults)-1 {
				m.searchCursor++
			}
		default:
			var cmd tea.Cmd
			m.searchInput, cmd = m.searchInput.Update(msg)
			m.performSearch()
			return m, cmd
		}
	}
	var cmd tea.Cmd
	m.searchInput, cmd = m.searchInput.Update(msg)
	return m, cmd
}

func (m interactiveModel) updateImpact(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			m.mode = modeTree
			m.impactPkg = nil
			m.impactInfo = nil
		}
	}
	return m, nil
}

func (m interactiveModel) updateUpgrade(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			m.mode = modeTree
			m.upgradePkg = nil
			m.upgradeInfo = nil
		}
	}
	return m, nil
}

func (m *interactiveModel) performSearch() {
	query := strings.ToLower(m.searchInput.Value())
	if query == "" {
		m.searchResults = nil
		m.searchCursor = 0
		return
	}

	var results []*treeNode
	for _, root := range m.roots {
		m.searchInTree(root, query, &results)
	}
	m.searchResults = results
	m.searchCursor = 0
}

func (m *interactiveModel) searchInTree(node *treeNode, query string, results *[]*treeNode) {
	if strings.Contains(strings.ToLower(node.Pkg.Name), query) {
		*results = append(*results, node)
	}
	for _, child := range node.Children {
		m.searchInTree(child, query, results)
	}
}

func (m *interactiveModel) expandToNode(target *treeNode) {
	m.expandToNodeInRoots(m.roots, target.Pkg.ID)
}

func (m *interactiveModel) expandToNodeInRoots(nodes []*treeNode, targetID string) bool {
	for _, node := range nodes {
		if node.Pkg.ID == targetID {
			return true
		}
		if m.expandToNodeInRoots(node.Children, targetID) {
			node.Expanded = true
			return true
		}
	}
	return false
}

func (m *interactiveModel) computeImpact(pkg *SBOMPackage) *ImpactInfo {
	info := &ImpactInfo{}

	var collectReverse func(pkgID string, visited map[string]bool)
	collectReverse = func(pkgID string, visited map[string]bool) {
		if visited[pkgID] {
			return
		}
		visited[pkgID] = true
		for _, parentID := range m.reverseDeps[pkgID] {
			if !visited[parentID] {
				info.ReverseDeps = append(info.ReverseDeps, parentID)
				collectReverse(parentID, visited)
			}
		}
	}
	collectReverse(pkg.ID, map[string]bool{})

	info.AffectedCount = len(info.ReverseDeps)

	pkgMap := make(map[string]*SBOMPackage)
	for i := range m.doc.Packages {
		pkgMap[m.doc.Packages[i].ID] = &m.doc.Packages[i]
	}

	visited := map[string]bool{pkg.ID: true}
	var collectDeps func(pkgID string)
	collectDeps = func(pkgID string) {
		for _, rel := range m.doc.Relationships {
			if rel.RelationshipType == "DEPENDS_ON" && rel.SourceID == pkgID && !visited[rel.TargetID] {
				visited[rel.TargetID] = true
				info.RemoveImpact = append(info.RemoveImpact, rel.TargetID)
				collectDeps(rel.TargetID)
			}
		}
	}
	collectDeps(pkg.ID)

	return info
}

func (m *interactiveModel) computeUpgrade(pkg *SBOMPackage) *UpgradeInfo {
	info := &UpgradeInfo{
		CurrentVersion: pkg.Version,
	}

	fixedVersions := make(map[string][]string)
	for _, vuln := range pkg.Vulnerabilities {
		if vuln.FixedVersion != "" {
			fixedVersions[vuln.FixedVersion] = append(fixedVersions[vuln.FixedVersion], vuln.CVE)
		}
	}

	for version, cves := range fixedVersions {
		info.AvailableVersions = append(info.AvailableVersions, FixedVersionInfo{
			Version:   version,
			FixedCVEs: cves,
		})
	}

	sort.Slice(info.AvailableVersions, func(i, j int) bool {
		return info.AvailableVersions[i].Version > info.AvailableVersions[j].Version
	})

	return info
}

func (m *interactiveModel) exportSubtree(node *treeNode) {
	subtree := m.buildSubtreeJSON(node)
	data, err := json.MarshalIndent(subtree, "", "  ")
	if err != nil {
		m.errMsg = fmt.Sprintf("导出失败: %v", err)
		return
	}

	if err := copyToClipboard(data); err != nil {
		tmpFile, fErr := os.CreateTemp("", "sbom-subtree-*.json")
		if fErr != nil {
			m.errMsg = "导出失败: 无法写入临时文件"
			return
		}
		defer tmpFile.Close()
		tmpFile.Write(data)
		m.errMsg = fmt.Sprintf("剪贴板不可用, 已保存到: %s", tmpFile.Name())
		return
	}
	m.errMsg = "子树已导出到剪贴板"
}

func (m *interactiveModel) buildSubtreeJSON(node *treeNode) map[string]interface{} {
	pkg := node.Pkg
	result := map[string]interface{}{
		"name":        pkg.Name,
		"version":     pkg.Version,
		"license":     pkg.LicenseConcluded,
		"risk_score":  pkg.RiskScore,
		"layer":       pkg.Provenance.LayerIndex,
		"direct":      pkg.Provenance.IsDirect,
	}

	if len(pkg.Vulnerabilities) > 0 {
		vulns := make([]map[string]interface{}, 0, len(pkg.Vulnerabilities))
		for _, v := range pkg.Vulnerabilities {
			vulns = append(vulns, map[string]interface{}{
				"cve":           v.CVE,
				"severity":      string(v.Severity),
				"fixed_version": v.FixedVersion,
			})
		}
		result["vulnerabilities"] = vulns
	}

	if len(node.Children) > 0 {
		children := make([]map[string]interface{}, 0, len(node.Children))
		for _, child := range node.Children {
			children = append(children, m.buildSubtreeJSON(child))
		}
		result["dependencies"] = children
	}

	return result
}

func copyToClipboard(data []byte) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(string(data))
	return cmd.Run()
}

func (m interactiveModel) View() string {
	switch m.mode {
	case modeTree:
		return m.viewTree()
	case modeSearch:
		return m.viewSearch()
	case modeImpact:
		return m.viewImpact()
	case modeUpgrade:
		return m.viewUpgrade()
	}
	return ""
}

func (m interactiveModel) viewTree() string {
	var sb strings.Builder

	sb.WriteString(styleHeader.Render(fmt.Sprintf("📦 SBOM 依赖树 — %s (%d 个包)", m.doc.ImageName, len(m.doc.Packages))))
	sb.WriteString("\n\n")

	for i, node := range m.flatNodes {
		prefix := m.buildTreePrefix(node)
		label := m.formatNodeLabel(node.Pkg)

		line := prefix + label
		if i == m.cursor {
			sb.WriteString(styleCursor.Render(line))
		} else {
			sb.WriteString(line)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(styleDim.Render("↑↓/jk:导航  Enter:展开/折叠  /:搜索  d:影响分析  u:升级信息  e:导出子树  q:退出"))
	if m.errMsg != "" {
		sb.WriteString("\n" + styleGreen.Render(m.errMsg))
	}
	sb.WriteString("\n")

	return sb.String()
}

func (m interactiveModel) buildTreePrefix(node *treeNode) string {
	if node.Depth == 0 {
		if len(node.Children) > 0 {
			if node.Expanded {
				return "▼ "
			}
			return "▶ "
		}
		return "  "
	}

	var parts []string
	for d := 0; d < node.Depth; d++ {
		parts = append(parts, "│   ")
	}

	if len(node.Children) > 0 {
		if node.Expanded {
			parts = append(parts, "├── ▼ ")
		} else {
			parts = append(parts, "├── ▶ ")
		}
	} else {
		parts = append(parts, "├── ")
	}

	return strings.Join(parts, "")
}

func (m interactiveModel) formatNodeLabel(pkg *SBOMPackage) string {
	hasVulns := len(pkg.Vulnerabilities) > 0
	highRisk := pkg.RiskScore > 70

	name := pkg.Name + "@" + pkg.Version
	lic := pkg.LicenseConcluded
	if lic == "" || lic == "NOASSERTION" {
		lic = "?"
	}
	layer := fmt.Sprintf("L%d", pkg.Provenance.LayerIndex)
	risk := fmt.Sprintf("风险:%.0f", pkg.RiskScore)

	label := fmt.Sprintf("%s / %s / %s / %s", name, lic, risk, layer)

	if hasVulns {
		label = styleRed.Render(label)
	} else if highRisk {
		label = styleYellow.Render(label)
	}

	return label
}

func (m interactiveModel) viewSearch() string {
	var sb strings.Builder

	sb.WriteString(styleHeader.Render("🔍 搜索依赖包"))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("搜索: %s", m.searchInput.View()))
	sb.WriteString("\n\n")

	if len(m.searchResults) > 0 {
		for i, node := range m.searchResults {
			label := fmt.Sprintf("%s@%s / %s / 风险:%.0f / L%d",
				node.Pkg.Name, node.Pkg.Version,
				node.Pkg.LicenseConcluded,
				node.Pkg.RiskScore,
				node.Pkg.Provenance.LayerIndex)
			if i == m.searchCursor {
				sb.WriteString(styleCursor.Render("  → " + label))
			} else {
				sb.WriteString("    " + label)
			}
			sb.WriteString("\n")
		}
		sb.WriteString(styleDim.Render("\n↑↓:选择  Enter:定位  Esc:返回"))
	} else if m.searchInput.Value() != "" {
		sb.WriteString(styleDim.Render("  无匹配结果"))
	} else {
		sb.WriteString(styleDim.Render("  输入包名开始搜索..."))
	}

	sb.WriteString("\n")
	return sb.String()
}

func (m interactiveModel) viewImpact() string {
	var sb strings.Builder

	pkg := m.impactPkg
	info := m.impactInfo

	sb.WriteString(styleHeader.Render(fmt.Sprintf("📊 影响范围分析 — %s@%s", pkg.Name, pkg.Version)))
	sb.WriteString("\n\n")

	pkgMap := make(map[string]*SBOMPackage)
	for i := range m.doc.Packages {
		pkgMap[m.doc.Packages[i].ID] = &m.doc.Packages[i]
	}

	sb.WriteString(styleCyan.Render("反向依赖 (哪些包依赖了它):"))
	sb.WriteString("\n")
	if len(info.ReverseDeps) > 0 {
		for _, depID := range info.ReverseDeps {
			if p, ok := pkgMap[depID]; ok {
				sb.WriteString(fmt.Sprintf("  ← %s@%s\n", p.Name, p.Version))
			} else {
				sb.WriteString(fmt.Sprintf("  ← %s\n", depID))
			}
		}
	} else {
		sb.WriteString(styleDim.Render("  无反向依赖 (顶层直接依赖)\n"))
	}

	sb.WriteString("\n")
	sb.WriteString(styleCyan.Render(fmt.Sprintf("移除影响: 共影响 %d 个包", info.AffectedCount+len(info.RemoveImpact))))
	sb.WriteString("\n")
	if len(info.RemoveImpact) > 0 {
		for _, depID := range info.RemoveImpact {
			if p, ok := pkgMap[depID]; ok {
				sb.WriteString(styleRed.Render(fmt.Sprintf("  ✗ %s@%s\n", p.Name, p.Version)))
			}
		}
	}

	sb.WriteString("\n")
	sb.WriteString(styleDim.Render("按 Esc 返回"))
	sb.WriteString("\n")

	return sb.String()
}

func (m interactiveModel) viewUpgrade() string {
	var sb strings.Builder

	pkg := m.upgradePkg
	info := m.upgradeInfo

	sb.WriteString(styleHeader.Render(fmt.Sprintf("⬆ 可用升级 — %s", pkg.Name)))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("当前版本: %s\n", styleBold.Render(info.CurrentVersion)))
	sb.WriteString("\n")

	if len(info.AvailableVersions) > 0 {
		sb.WriteString(styleCyan.Render("可升级版本:"))
		sb.WriteString("\n")
		for _, v := range info.AvailableVersions {
			sb.WriteString(styleGreen.Render(fmt.Sprintf("  → %s\n", v.Version)))
			if len(v.FixedCVEs) > 0 {
				sb.WriteString(styleYellow.Render(fmt.Sprintf("    修复: %s\n", strings.Join(v.FixedCVEs, ", "))))
			}
		}
	} else {
		sb.WriteString(styleDim.Render("  无可用升级版本 (未发现已知修复版本)"))
	}

	sb.WriteString("\n")
	sb.WriteString(styleDim.Render("按 Esc 返回"))
	sb.WriteString("\n")

	return sb.String()
}
