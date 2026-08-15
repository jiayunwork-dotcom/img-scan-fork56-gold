package utils

import "testing"

func TestTruncateString_ExactMaxLen(t *testing.T) {
	got := TruncateString("hello", 5)
	if got != "hello" {
		t.Fatalf("TruncateString(%q, 5)=%q, want hello", "hello", got)
	}
}
