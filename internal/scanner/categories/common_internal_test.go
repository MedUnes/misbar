package categories

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateRuneAware(t *testing.T) {
	// 100 two-byte runes (200 bytes); truncating "to 80" must not split a rune.
	s := strings.Repeat("é", 100)
	got := truncate(s, 80)
	if !utf8.ValidString(got) {
		t.Errorf("truncate produced invalid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated string should end with an ellipsis: %q", got)
	}

	if truncate("short", 80) != "short" {
		t.Error("a short string should be returned unchanged")
	}
}
