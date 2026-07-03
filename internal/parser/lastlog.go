package parser

import (
	"bytes"
	"encoding/binary"
	"os"
	"time"
)

// lastlogRecordSize is the size of one /var/log/lastlog record: fixed 292 bytes,
// indexed by UID (record N lives at offset N*292).
const lastlogRecordSize = 292

// lastlogRecord mirrors struct lastlog field-for-field.
type lastlogRecord struct {
	Time int32
	Line [32]byte
	Host [256]byte
}

// LastlogEntry is a decoded last-login record for one UID.
type LastlogEntry struct {
	UID  int
	Line string
	Host string
	Time time.Time
}

// ParseLastlog decodes lastlog bytes. The record index is the UID; records with
// a zero timestamp (never logged in) are skipped.
func ParseLastlog(data []byte) []LastlogEntry {
	var out []LastlogEntry
	for uid := 0; len(data) >= lastlogRecordSize; uid++ {
		var rec lastlogRecord
		_ = binary.Read(bytes.NewReader(data[:lastlogRecordSize]), binary.LittleEndian, &rec)
		data = data[lastlogRecordSize:]
		if rec.Time == 0 {
			continue
		}
		out = append(out, LastlogEntry{
			UID:  uid,
			Line: cString(rec.Line[:]),
			Host: cString(rec.Host[:]),
			Time: time.Unix(int64(rec.Time), 0),
		})
	}
	return out
}

// ParseLastlogFile reads and decodes /var/log/lastlog.
func ParseLastlogFile(path string) ([]LastlogEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseLastlog(data), nil
}
