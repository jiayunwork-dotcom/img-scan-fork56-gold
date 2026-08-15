package sbom

import (
	"regexp"
	"strings"
	"sync"
	"unicode"
)

type spdxLicenseTemplate struct {
	ID       string
	Name     string
	Keywords []string
	Patterns []string
}

var licenseTemplates []spdxLicenseTemplate
var licenseOnce sync.Once
var compiledPatterns map[string][]*regexp.Regexp

func initLicenseTemplates() {
	licenseTemplates = []spdxLicenseTemplate{
		{ID: "MIT", Name: "MIT License", Keywords: []string{"mit license", "permission is hereby granted", "subject to the following conditions"}, Patterns: []string{`(?i)permission is hereby granted.*subject to the following conditions`}},
		{ID: "Apache-2.0", Name: "Apache License 2.0", Keywords: []string{"apache license", "version 2.0", "licensed under the apache license"}, Patterns: []string{`(?i)apache license.*version 2\.0`, `(?i)licensed under the apache license.*version 2\.0`}},
		{ID: "GPL-2.0-only", Name: "GNU General Public License v2.0 only", Keywords: []string{"gnu general public license", "version 2", "gpl"}, Patterns: []string{`(?i)gnu general public license.*version 2`}},
		{ID: "GPL-3.0-only", Name: "GNU General Public License v3.0 only", Keywords: []string{"gnu general public license", "version 3", "gplv3"}, Patterns: []string{`(?i)gnu general public license.*version 3`}},
		{ID: "BSD-2-Clause", Name: "BSD 2-Clause License", Keywords: []string{"bsd", "redistribution and use", "two-clause"}, Patterns: []string{`(?i)redistribution and use.*source and binary.*retain the above copyright`}},
		{ID: "BSD-3-Clause", Name: "BSD 3-Clause License", Keywords: []string{"bsd", "redistribution and use", "three-clause", "contributors may be used"}, Patterns: []string{`(?i)redistribution and use.*source and binary.*neither the name.*nor the names of its contributors`}},
		{ID: "ISC", Name: "ISC License", Keywords: []string{"isc license", "permission to use", "is hereby granted"}, Patterns: []string{`(?i)isc license`, `(?i)permission to use.*copy.*modify.*and.*distribute`}},
		{ID: "MPL-2.0", Name: "Mozilla Public License 2.0", Keywords: []string{"mozilla public license", "version 2.0", "mpl"}, Patterns: []string{`(?i)mozilla public license.*version 2\.0`}},
		{ID: "LGPL-2.1-only", Name: "GNU Lesser General Public License v2.1 only", Keywords: []string{"lesser general public license", "lgpl", "version 2.1"}, Patterns: []string{`(?i)lesser general public license.*version 2\.1`}},
		{ID: "LGPL-3.0-only", Name: "GNU Lesser General Public License v3.0 only", Keywords: []string{"lesser general public license", "lgpl", "version 3"}, Patterns: []string{`(?i)lesser general public license.*version 3`}},
		{ID: "AGPL-3.0-only", Name: "GNU Affero General Public License v3.0 only", Keywords: []string{"affero general public license", "agpl"}, Patterns: []string{`(?i)affero general public license`}},
		{ID: "Unlicense", Name: "The Unlicense", Keywords: []string{"unlicense", "public domain", "unlicensed"}, Patterns: []string{`(?i)this is free and unencumbered software released into the public domain`}},
		{ID: "CC0-1.0", Name: "Creative Commons Zero v1.0 Universal", Keywords: []string{"creative commons", "cc0", "public domain dedication"}, Patterns: []string{`(?i)creative commons zero`, `(?i)cc0.*public domain dedication`}},
		{ID: "EPL-2.0", Name: "Eclipse Public License 2.0", Keywords: []string{"eclipse public license", "epl", "version 2.0"}, Patterns: []string{`(?i)eclipse public license.*version 2\.0`}},
		{ID: "CDDL-1.1", Name: "Common Development and Distribution License 1.1", Keywords: []string{"common development and distribution license", "cddl"}, Patterns: []string{`(?i)common development and distribution license`}},
		{ID: "Artistic-2.0", Name: "Artistic License 2.0", Keywords: []string{"artistic license", "version 2.0"}, Patterns: []string{`(?i)artistic license.*2\.0`}},
		{ID: "Zlib", Name: "zlib License", Keywords: []string{"zlib", "zlib license"}, Patterns: []string{`(?i)zlib license`, `(?i)this software is provided .+as is.+without express or implied warranty`}},
		{ID: "PostgreSQL", Name: "PostgreSQL License", Keywords: []string{"postgresql", "postgres"}, Patterns: []string{`(?i)permission to use.*copy.*modify.*and distribute this software.*postgresql`}},
		{ID: "Python-2.0", Name: "Python License 2.0", Keywords: []string{"python license", "psf license", "python software foundation"}, Patterns: []string{`(?i)python software foundation license`, `(?i)psf license`}},
		{ID: "0BSD", Name: "Zero-Clause BSD", Keywords: []string{"zero-clause bsd", "0bsd", "free for any purpose"}, Patterns: []string{`(?i)zero-clause bsd`, `(?i)permission to use.*copy.*modify.*and.*distribute this software.*free for any purpose`}},
	}

	compiledPatterns = make(map[string][]*regexp.Regexp)
	for _, tmpl := range licenseTemplates {
		var compiled []*regexp.Regexp
		for _, p := range tmpl.Patterns {
			re, err := regexp.Compile(p)
			if err == nil {
				compiled = append(compiled, re)
			}
		}
		compiledPatterns[tmpl.ID] = compiled
	}
}

var commonLicenseAliases = map[string]string{
	"mit":                "MIT",
	"mit license":        "MIT",
	"apache 2.0":         "Apache-2.0",
	"apache-2.0":         "Apache-2.0",
	"apache license 2.0": "Apache-2.0",
	"apache license, version 2.0": "Apache-2.0",
	"apache-2":           "Apache-2.0",
	"gplv2":              "GPL-2.0-only",
	"gplv2+":             "GPL-2.0-or-later",
	"gpl-2.0":            "GPL-2.0-only",
	"gpl-2.0+":           "GPL-2.0-or-later",
	"gplv3":              "GPL-3.0-only",
	"gplv3+":             "GPL-3.0-or-later",
	"gpl-3.0":            "GPL-3.0-only",
	"gpl-3.0+":           "GPL-3.0-or-later",
	"lgpl-2.1":           "LGPL-2.1-only",
	"lgpl-2.1+":          "LGPL-2.1-or-later",
	"lgpl-3.0":           "LGPL-3.0-only",
	"lgpl-3.0+":          "LGPL-3.0-or-later",
	"bsd-2-clause":       "BSD-2-Clause",
	"bsd-3-clause":       "BSD-3-Clause",
	"bsd-2-clausebsd":    "BSD-2-Clause",
	"bsd":                "BSD-3-Clause",
	"isc":                "ISC",
	"isc license":        "ISC",
	"mpl-2.0":            "MPL-2.0",
	"mpl2":               "MPL-2.0",
	"cc0":                "CC0-1.0",
	"cc0-1.0":            "CC0-1.0",
	"unlicense":          "Unlicense",
	"public domain":      "Unlicense",
	"zlib":               "Zlib",
	"epl-2.0":            "EPL-2.0",
	"cddl-1.1":           "CDDL-1.1",
	"artistic-2.0":       "Artistic-2.0",
	"python-2.0":         "Python-2.0",
	"psf-2.0":            "Python-2.0",
	"0bsd":               "0BSD",
	"agpl-3.0":           "AGPL-3.0-only",
	"agpl-3.0+":          "AGPL-3.0-or-later",
}

type LicenseScanner struct {
	mu sync.Mutex
}

func NewLicenseScanner() *LicenseScanner {
	licenseOnce.Do(initLicenseTemplates)
	return &LicenseScanner{}
}

func (ls *LicenseScanner) IdentifyLicense(content []byte, filePath string) LicenseMatch {
	text := strings.ToLower(string(content))
	text = strings.TrimSpace(text)

	if text == "" {
		return LicenseMatch{SPDXID: "NOASSERTION", Confidence: 0, OriginalText: ""}
	}

	if match := ls.matchByAlias(text); match.Confidence > 0 {
		return match
	}

	if match := ls.matchByPattern(text); match.Confidence > 0 {
		return match
	}

	if match := ls.matchBySimilarity(text); match.Confidence > 0 {
		return match
	}

	customID := "LicenseRef-" + sanitizeLicenseRef(filePath)
	return LicenseMatch{SPDXID: customID, Confidence: 0, OriginalText: truncateText(text, 200)}
}

func (ls *LicenseScanner) IdentifyLicenseString(licenseStr string) LicenseMatch {
	if licenseStr == "" {
		return LicenseMatch{SPDXID: "NOASSERTION", Confidence: 0, OriginalText: ""}
	}

	compound := ls.parseCompoundLicense(licenseStr)
	if len(compound) > 0 {
		return LicenseMatch{SPDXID: compound, Confidence: 1.0, OriginalText: licenseStr}
	}

	lower := strings.ToLower(strings.TrimSpace(licenseStr))
	if spdxID, ok := commonLicenseAliases[lower]; ok {
		return LicenseMatch{SPDXID: spdxID, Confidence: 1.0, OriginalText: licenseStr}
	}

	for _, tmpl := range licenseTemplates {
		if strings.EqualFold(tmpl.ID, licenseStr) || strings.EqualFold(tmpl.Name, licenseStr) {
			return LicenseMatch{SPDXID: tmpl.ID, Confidence: 1.0, OriginalText: licenseStr}
		}
	}

	return LicenseMatch{SPDXID: "NOASSERTION", Confidence: 0, OriginalText: licenseStr}
}

func (ls *LicenseScanner) matchByAlias(text string) LicenseMatch {
	cleaned := strings.TrimSpace(text)
	cleaned = strings.TrimPrefix(cleaned, "license:")
	cleaned = strings.TrimPrefix(cleaned, "license")
	cleaned = strings.TrimSpace(cleaned)

	if spdxID, ok := commonLicenseAliases[strings.ToLower(cleaned)]; ok {
		return LicenseMatch{SPDXID: spdxID, Confidence: 1.0, OriginalText: cleaned}
	}

	for _, tmpl := range licenseTemplates {
		if strings.EqualFold(tmpl.Name, cleaned) || strings.EqualFold(tmpl.ID, cleaned) {
			return LicenseMatch{SPDXID: tmpl.ID, Confidence: 1.0, OriginalText: cleaned}
		}
	}

	return LicenseMatch{}
}

func (ls *LicenseScanner) matchByPattern(text string) LicenseMatch {
	bestMatch := LicenseMatch{}
	bestConfidence := 0.0

	for _, tmpl := range licenseTemplates {
		patterns, ok := compiledPatterns[tmpl.ID]
		if !ok {
			continue
		}

		matchedCount := 0
		for _, re := range patterns {
			if re.MatchString(text) {
				matchedCount++
			}
		}

		if matchedCount > 0 {
			confidence := float64(matchedCount) / float64(len(patterns))
			keywordHits := 0
			for _, kw := range tmpl.Keywords {
				if strings.Contains(text, strings.ToLower(kw)) {
					keywordHits++
				}
			}
			if keywordHits > 0 {
				confidence += float64(keywordHits) / float64(len(tmpl.Keywords)) * 0.3
			}
			if confidence > 1.0 {
				confidence = 1.0
			}

			if confidence > bestConfidence {
				bestConfidence = confidence
				bestMatch = LicenseMatch{
					SPDXID:       tmpl.ID,
					Confidence:   confidence,
					OriginalText: truncateText(text, 200),
				}
			}
		}
	}

	return bestMatch
}

func (ls *LicenseScanner) matchBySimilarity(text string) LicenseMatch {
	bestMatch := LicenseMatch{}
	bestScore := 0.0

	textWords := extractWords(text)

	for _, tmpl := range licenseTemplates {
		templateText := strings.ToLower(tmpl.Name + " " + strings.Join(tmpl.Keywords, " "))
		templateWords := extractWords(templateText)

		score := jaccardSimilarity(textWords, templateWords)
		if score > bestScore {
			bestScore = score
			bestMatch = LicenseMatch{
				SPDXID:       tmpl.ID,
				Confidence:   score,
				OriginalText: truncateText(text, 200),
			}
		}
	}

	if bestScore >= 0.85 {
		return bestMatch
	}

	if bestScore >= 0.5 {
		bestMatch.Confidence = bestScore
		return bestMatch
	}

	return LicenseMatch{}
}

func (ls *LicenseScanner) parseCompoundLicense(licenseStr string) string {
	licenseStr = strings.TrimSpace(licenseStr)

	if strings.Contains(licenseStr, " WITH ") {
		parts := strings.SplitN(licenseStr, " WITH ", 2)
		base := ls.normalizeSingle(parts[0])
		exception := strings.TrimSpace(parts[1])
		if base != "NOASSERTION" {
			return base + " WITH " + exception
		}
	}

	if strings.Contains(licenseStr, " OR ") {
		parts := strings.Split(licenseStr, " OR ")
		var normalized []string
		for _, p := range parts {
			n := ls.normalizeSingle(strings.TrimSpace(p))
			normalized = append(normalized, n)
		}
		return strings.Join(normalized, " OR ")
	}

	if strings.Contains(licenseStr, " AND ") {
		parts := strings.Split(licenseStr, " AND ")
		var normalized []string
		for _, p := range parts {
			n := ls.normalizeSingle(strings.TrimSpace(p))
			normalized = append(normalized, n)
		}
		return strings.Join(normalized, " AND ")
	}

	return ""
}

func (ls *LicenseScanner) normalizeSingle(licenseStr string) string {
	lower := strings.ToLower(strings.TrimSpace(licenseStr))
	if spdxID, ok := commonLicenseAliases[lower]; ok {
		return spdxID
	}
	for _, tmpl := range licenseTemplates {
		if strings.EqualFold(tmpl.ID, licenseStr) || strings.EqualFold(tmpl.Name, licenseStr) {
			return tmpl.ID
		}
	}
	return "NOASSERTION"
}

func jaccardSimilarity(setA, setB map[string]bool) float64 {
	if len(setA) == 0 && len(setB) == 0 {
		return 1.0
	}
	if len(setA) == 0 || len(setB) == 0 {
		return 0.0
	}

	intersection := 0
	for w := range setA {
		if setB[w] {
			intersection++
		}
	}

	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

func extractWords(text string) map[string]bool {
	words := make(map[string]bool)
	var current strings.Builder

	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current.WriteRune(unicode.ToLower(r))
		} else {
			if current.Len() > 2 {
				words[current.String()] = true
			}
			current.Reset()
		}
	}
	if current.Len() > 2 {
		words[current.String()] = true
	}

	return words
}

func sanitizeLicenseRef(path string) string {
	result := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return '-'
	}, path)
	if len(result) > 50 {
		result = result[:50]
	}
	return result
}

func truncateText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen] + "..."
}

func ScanLicensesForPackages(licenseFiles map[string][]byte, scanner *LicenseScanner) map[string]string {
	pkgLicenses := make(map[string]string)

	for path, content := range licenseFiles {
		match := scanner.IdentifyLicense(content, path)
		dir := path
		if idx := strings.LastIndex(dir, "/"); idx != -1 {
			dir = dir[:idx]
		}
		pkgLicenses[dir] = match.SPDXID
	}

	return pkgLicenses
}

func FindLicenseForPackage(pkgPath string, pkgLicenses map[string]string) string {
	if pkgPath == "" {
		return ""
	}

	dir := pkgPath
	if idx := strings.LastIndex(dir, "/"); idx != -1 {
		dir = dir[:idx]
	}

	if lic, ok := pkgLicenses[dir]; ok {
		return lic
	}

	parts := strings.Split(dir, "/")
	for i := len(parts) - 1; i >= 1; i-- {
		parent := strings.Join(parts[:i], "/")
		if lic, ok := pkgLicenses[parent]; ok {
			return lic
		}
	}

	return ""
}
