package parser

import (
	"encoding/xml"
	"os"
	"slices"
	"time"
)

// RecentFile is one entry from a recently-used.xbel bookmark file.
type RecentFile struct {
	Href     string
	Modified time.Time
}

// ParseXBEL parses a GNOME recently-used.xbel document and returns its bookmarks
// sorted most-recently-modified first.
func ParseXBEL(data []byte) ([]RecentFile, error) {
	var doc struct {
		Bookmarks []struct {
			Href     string `xml:"href,attr"`
			Modified string `xml:"modified,attr"`
		} `xml:"bookmark"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	out := make([]RecentFile, 0, len(doc.Bookmarks))
	for _, b := range doc.Bookmarks {
		t, _ := time.Parse(time.RFC3339, b.Modified) // zero time if unparseable
		out = append(out, RecentFile{Href: b.Href, Modified: t})
	}
	slices.SortFunc(out, func(a, b RecentFile) int {
		return b.Modified.Compare(a.Modified) // descending
	})
	return out, nil
}

// ParseXBELFile reads and parses a recently-used.xbel file.
func ParseXBELFile(path string) ([]RecentFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseXBEL(data)
}
