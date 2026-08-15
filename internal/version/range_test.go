package version

import "testing"

func TestVersionSatisfiesRange_GreaterOrEqualBoundary(t *testing.T) {
	if !VersionSatisfiesRange("1.2.0", ">=1.2.0", "semver") {
		t.Fatal(`VersionSatisfiesRange("1.2.0", ">=1.2.0", "semver") = false, want true`)
	}
}
