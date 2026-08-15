package diff

import (
	"testing"

	"imgscan/internal/config"
)

func TestHasNewCriticalOrHigh_DetectsHigh(t *testing.T) {
	d := &config.DiffResult{
		VulnerabilityDiff: config.VulnerabilityDiff{
			Added: []config.Vulnerability{{
				CVE:      "CVE-2024-1",
				Severity: config.SeverityHigh,
			}},
		},
	}
	_, hasHigh := HasNewCriticalOrHigh(d)
	if !hasHigh {
		t.Fatal("HasNewCriticalOrHigh with a new High vuln: hasHigh=false, want true")
	}
}
