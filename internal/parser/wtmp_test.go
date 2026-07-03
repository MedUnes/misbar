package parser

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildUtmp assembles one 384-byte utmp record at the documented field offsets.
func buildUtmp(typ int16, user, line, host string, ts time.Time) []byte {
	b := make([]byte, utmpRecordSize)
	binary.LittleEndian.PutUint16(b[0:], uint16(typ))
	copy(b[8:40], line)
	copy(b[44:76], user)
	copy(b[76:332], host)
	binary.LittleEndian.PutUint32(b[340:], uint32(ts.Unix()))
	return b
}

func TestParseUtmp(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	var data []byte
	data = append(data, buildUtmp(utUserProcess, "alice", "pts/0", "10.0.0.5", ts)...)
	data = append(data, buildUtmp(utBootTime, "reboot", "~", "", ts)...)
	data = append(data, buildUtmp(utUserProcess, "root", "tty1", "", ts)...)
	data = append(data, 1, 2, 3) // trailing partial record must be ignored

	entries := ParseUtmp(data)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	e := entries[0]
	if e.User != "alice" || e.Line != "pts/0" || e.Host != "10.0.0.5" {
		t.Errorf("entry0 = %+v", e)
	}
	if !e.Time.Equal(ts) {
		t.Errorf("entry0 time = %v, want %v", e.Time, ts)
	}
	if !e.IsUserProcess() {
		t.Error("entry0 should be a user process")
	}
	if !entries[1].IsBootTime() {
		t.Error("entry1 should be a boot-time record")
	}

	if got := len(Sessions(entries)); got != 2 {
		t.Errorf("Sessions = %d, want 2 (alice, root)", got)
	}
	if got := len(FailedLogins(entries)); got != 3 {
		t.Errorf("FailedLogins = %d, want 3", got)
	}
}

func TestParseUtmpEdgeCases(t *testing.T) {
	if got := ParseUtmp(nil); len(got) != 0 {
		t.Errorf("nil → %d entries, want 0", len(got))
	}
	if got := ParseUtmp(make([]byte, utmpRecordSize-1)); len(got) != 0 {
		t.Errorf("sub-record → %d entries, want 0", len(got))
	}
}
