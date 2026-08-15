package version

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/Masterminds/semver/v3"
)

type VersionCompareFunc func(a, b string) int

func CompareSemver(a, b string) int {
	va, err := semver.NewVersion(a)
	if err != nil {
		return -1
	}
	vb, err := semver.NewVersion(b)
	if err != nil {
		return 1
	}
	return va.Compare(vb)
}

func CompareDeb(a, b string) int {
	return compareDebianVersions(a, b)
}

func CompareRPM(a, b string) int {
	return compareRPMVersions(a, b)
}

func CompareAPK(a, b string) int {
	return CompareDeb(a, b)
}

func GetComparer(pkgType string) VersionCompareFunc {
	switch pkgType {
	case "deb", "apk":
		return CompareDeb
	case "rpm":
		return CompareRPM
	default:
		return CompareSemver
	}
}

func compareDebianVersions(a, b string) int {
	aEpoch, aVersion, aRevision := splitDebianVersion(a)
	bEpoch, bVersion, bRevision := splitDebianVersion(b)

	if aEpoch != bEpoch {
		if aEpoch > bEpoch {
			return 1
		}
		return -1
	}

	if cmp := compareDebianVersionParts(aVersion, bVersion); cmp != 0 {
		return cmp
	}

	return compareDebianVersionParts(aRevision, bRevision)
}

func splitDebianVersion(v string) (epoch int, version, revision string) {
	epoch = 0
	revision = "0"

	if idx := strings.Index(v, ":"); idx != -1 {
		epoch, _ = strconv.Atoi(v[:idx])
		v = v[idx+1:]
	}

	if idx := strings.LastIndex(v, "-"); idx != -1 {
		revision = v[idx+1:]
		v = v[:idx]
	}

	version = v
	return
}

func compareDebianVersionParts(a, b string) int {
	aParts := splitDebianVersionString(a)
	bParts := splitDebianVersionString(b)

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var aPart, bPart string
		if i < len(aParts) {
			aPart = aParts[i]
		}
		if i < len(bParts) {
			bPart = bParts[i]
		}

		if aPart == "" {
			if isNonDigit(bPart) {
				return 1
			}
			return -1
		}
		if bPart == "" {
			if isNonDigit(aPart) {
				return -1
			}
			return 1
		}

		aIsDigit := isDigit(aPart)
		bIsDigit := isDigit(bPart)

		if aIsDigit && bIsDigit {
			ai, _ := strconv.Atoi(aPart)
			bi, _ := strconv.Atoi(bPart)
			if ai != bi {
				if ai > bi {
					return 1
				}
				return -1
			}
		} else if !aIsDigit && !bIsDigit {
			if cmp := strings.Compare(aPart, bPart); cmp != 0 {
				return cmp
			}
		} else if aIsDigit {
			return -1
		} else {
			return 1
		}
	}

	return 0
}

func splitDebianVersionString(s string) []string {
	var parts []string
	if s == "" {
		return parts
	}

	var current strings.Builder
	currentIsDigit := unicode.IsDigit(rune(s[0]))

	for _, ch := range s {
		isDigit := unicode.IsDigit(ch)
		if isDigit != currentIsDigit {
			parts = append(parts, current.String())
			current.Reset()
			currentIsDigit = isDigit
		}
		current.WriteRune(ch)
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

func isDigit(s string) bool {
	for _, ch := range s {
		if !unicode.IsDigit(ch) {
			return false
		}
	}
	return s != ""
}

func isNonDigit(s string) bool {
	return !isDigit(s)
}

func compareRPMVersions(a, b string) int {
	aEpoch, aVersion, aRelease := splitRPMVersion(a)
	bEpoch, bVersion, bRelease := splitRPMVersion(b)

	if aEpoch != bEpoch {
		if aEpoch > bEpoch {
			return 1
		}
		return -1
	}

	if cmp := compareRPMParts(aVersion, bVersion); cmp != 0 {
		return cmp
	}

	return compareRPMParts(aRelease, bRelease)
}

func splitRPMVersion(v string) (epoch int, version, release string) {
	epoch = 0
	release = ""

	if idx := strings.Index(v, ":"); idx != -1 {
		epoch, _ = strconv.Atoi(v[:idx])
		v = v[idx+1:]
	}

	if idx := strings.LastIndex(v, "-"); idx != -1 {
		release = v[idx+1:]
		v = v[:idx]
	}

	version = v
	return
}

func compareRPMParts(a, b string) int {
	aParts := splitRPMParts(a)
	bParts := splitRPMParts(b)

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var aPart, bPart string
		if i < len(aParts) {
			aPart = aParts[i]
		}
		if i < len(bParts) {
			bPart = bParts[i]
		}

		if aPart == "" && bPart == "" {
			continue
		}
		if aPart == "" {
			return -1
		}
		if bPart == "" {
			return 1
		}

		aIsDigit := isDigit(aPart)
		bIsDigit := isDigit(bPart)

		if aIsDigit && bIsDigit {
			ai, _ := strconv.ParseInt(aPart, 10, 64)
			bi, _ := strconv.ParseInt(bPart, 10, 64)
			if ai != bi {
				if ai > bi {
					return 1
				}
				return -1
			}
		} else if !aIsDigit && !bIsDigit {
			if aPart == "~" {
				return -1
			}
			if bPart == "~" {
				return 1
			}
			if aPart == "^" {
				if bPart == "^" {
					continue
				}
				if i+1 >= len(bParts) || isDigit(bParts[i+1]) {
					return 1
				}
				return -1
			}
			if bPart == "^" {
				if i+1 >= len(aParts) || isDigit(aParts[i+1]) {
					return -1
				}
				return 1
			}
			if cmp := strings.Compare(aPart, bPart); cmp != 0 {
				return cmp
			}
		} else if aIsDigit {
			return 1
		} else {
			return -1
		}
	}

	return 0
}

var rpmSplitRe = regexp.MustCompile(`([a-zA-Z]+|[0-9]+|~|\^)`)

func splitRPMParts(s string) []string {
	var parts []string
	if s == "" {
		return parts
	}

	matches := rpmSplitRe.FindAllString(s, -1)
	return matches
}

func VersionSatisfiesRange(version, rangeStr, pkgType string) bool {
	comparer := GetComparer(pkgType)

	rangeStr = strings.TrimSpace(rangeStr)
	if rangeStr == "" {
		return true
	}

	parts := strings.Split(rangeStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if !checkSingleConstraint(version, part, comparer) {
			return false
		}
	}

	return true
}

func checkSingleConstraint(version, constraint string, comparer VersionCompareFunc) bool {
	switch {
	case strings.HasPrefix(constraint, ">="):
		v := strings.TrimPrefix(constraint, ">=")
		return comparer(version, v) > 0
	case strings.HasPrefix(constraint, "<="):
		v := strings.TrimPrefix(constraint, "<=")
		return comparer(version, v) <= 0
	case strings.HasPrefix(constraint, ">"):
		v := strings.TrimPrefix(constraint, ">")
		return comparer(version, v) > 0
	case strings.HasPrefix(constraint, "<"):
		v := strings.TrimPrefix(constraint, "<")
		return comparer(version, v) < 0
	case strings.HasPrefix(constraint, "="):
		v := strings.TrimPrefix(constraint, "=")
		return comparer(version, v) == 0
	default:
		return comparer(version, constraint) == 0
	}
}
