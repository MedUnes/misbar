package parser

import "testing"

func TestParseXBEL(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0">
  <bookmark href="file:///home/alice/old.txt" modified="2024-01-01T10:00:00Z"/>
  <bookmark href="file:///home/alice/new.pdf" modified="2024-06-01T10:00:00Z"/>
</xbel>`
	files, err := ParseXBEL([]byte(doc))
	if err != nil {
		t.Fatalf("ParseXBEL: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d bookmarks, want 2", len(files))
	}
	// Sorted most-recent first.
	if files[0].Href != "file:///home/alice/new.pdf" {
		t.Errorf("first = %q, want the newer bookmark", files[0].Href)
	}
}

func TestParseXBELInvalid(t *testing.T) {
	if _, err := ParseXBEL([]byte("this is not xml")); err == nil {
		t.Error("expected an error for non-XML input")
	}
}
