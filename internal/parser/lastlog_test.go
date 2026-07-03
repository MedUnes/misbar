package parser

import (
	"encoding/binary"
	"testing"
)

// buildLastlog assembles one 292-byte lastlog record.
func buildLastlog(tsec int32, line, host string) []byte {
	b := make([]byte, lastlogRecordSize)
	binary.LittleEndian.PutUint32(b[0:], uint32(tsec))
	copy(b[4:36], line)
	copy(b[36:292], host)
	return b
}

func TestParseLastlog(t *testing.T) {
	var data []byte
	data = append(data, buildLastlog(0, "", "")...)                       // uid 0, never logged in
	data = append(data, buildLastlog(1700000000, "pts/0", "10.0.0.5")...) // uid 1
	data = append(data, buildLastlog(0, "", "")...)                       // uid 2, never

	entries := ParseLastlog(data)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1 (zero-time records skipped)", len(entries))
	}
	e := entries[0]
	if e.UID != 1 || e.Line != "pts/0" || e.Host != "10.0.0.5" {
		t.Errorf("entry = %+v, want uid 1 pts/0 10.0.0.5", e)
	}
	if e.Time.Unix() != 1700000000 {
		t.Errorf("time = %d, want 1700000000", e.Time.Unix())
	}
}
