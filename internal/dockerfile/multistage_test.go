package dockerfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChecker_MultiStageTwoFrom(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	body := "FROM golang:1.22 AS build\nWORKDIR /src\nFROM alpine:3.19\nCOPY --from=build /src/app /app\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := NewChecker(path).Check()
	if err != nil {
		t.Fatal(err)
	}
	for _, iss := range issues {
		if iss.RuleID == "DF-BP-0001" {
			t.Fatalf("two-FROM Dockerfile reported %s, want no multi-stage warning", iss.RuleID)
		}
	}
}
