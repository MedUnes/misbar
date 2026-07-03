// Package parser decodes binary and semi-structured forensic artifacts: the
// utmp/wtmp/btmp login database, lastlog, syslog severity, and the GNOME
// recently-used.xbel file.
package parser

import (
	"bytes"
	"encoding/binary"
	"os"
	"time"
)

// utmpRecordSize is the size of glibc's struct utmp on Linux: a fixed 384 bytes,
// identical on amd64 and arm64 (the only architectures misbar ships for).
const utmpRecordSize = 384

// ut_type values (bits/utmp.h). We only care about a couple.
const (
	utBootTime    int16 = 2
	utUserProcess int16 = 7
)

// utmpRecord mirrors struct utmp field-for-field. encoding/binary reads fields
// sequentially (blank fields are padding), so this decodes the on-disk layout
// regardless of Go's in-memory alignment.
type utmpRecord struct {
	Type    int16
	_       [2]byte // padding to align Pid
	Pid     int32
	Line    [32]byte
	ID      [4]byte
	User    [32]byte
	Host    [256]byte
	Exit    [4]byte
	Session int32
	TvSec   int32
	TvUsec  int32
	AddrV6  [4]int32
	_       [20]byte
}

// UtmpEntry is a decoded, human-friendly login-database record.
type UtmpEntry struct {
	Type int16
	User string
	Line string // tty / pts
	Host string // origin host or IP
	PID  int32
	Time time.Time
}

// IsUserProcess reports whether the entry is a real login session (as opposed
// to boot markers, run-level changes, etc.).
func (e UtmpEntry) IsUserProcess() bool { return e.Type == utUserProcess }

// IsBootTime reports whether the entry marks a system boot.
func (e UtmpEntry) IsBootTime() bool { return e.Type == utBootTime }

// ParseUtmp decodes wtmp/btmp/utmp bytes into records. It reads fixed 384-byte
// records; any trailing partial record is ignored. Little-endian only — the
// shipped architectures (amd64, arm64) are both LE; big-endian is out of scope.
func ParseUtmp(data []byte) []UtmpEntry {
	out := make([]UtmpEntry, 0, len(data)/utmpRecordSize)
	for len(data) >= utmpRecordSize {
		var rec utmpRecord
		// Read from a fixed-size slice; error is impossible for the exact size.
		_ = binary.Read(bytes.NewReader(data[:utmpRecordSize]), binary.LittleEndian, &rec)
		data = data[utmpRecordSize:]
		out = append(out, UtmpEntry{
			Type: rec.Type,
			User: cString(rec.User[:]),
			Line: cString(rec.Line[:]),
			Host: cString(rec.Host[:]),
			PID:  rec.Pid,
			Time: time.Unix(int64(rec.TvSec), int64(rec.TvUsec)*1000),
		})
	}
	return out
}

// ParseUtmpFile reads and decodes a utmp-format file (wtmp, btmp, utmp).
func ParseUtmpFile(path string) ([]UtmpEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseUtmp(data), nil
}

// Sessions returns only the real login sessions (ut_type == USER_PROCESS) with
// a non-empty user — the `last`-style view of wtmp.
func Sessions(entries []UtmpEntry) []UtmpEntry {
	var out []UtmpEntry
	for _, e := range entries {
		if e.IsUserProcess() && e.User != "" {
			out = append(out, e)
		}
	}
	return out
}

// FailedLogins returns entries with a recorded user or tty — the `lastb`-style
// view of btmp, where every record is a failed attempt.
func FailedLogins(entries []UtmpEntry) []UtmpEntry {
	var out []UtmpEntry
	for _, e := range entries {
		if e.User != "" || e.Line != "" {
			out = append(out, e)
		}
	}
	return out
}

// cString converts a NUL-terminated fixed byte field to a Go string.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
