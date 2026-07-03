package scanner

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var aggNow = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

func aggEnv(t *testing.T, files map[string][]byte) *Env {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return NewEnv(root, time.Hour, WithClock(func() time.Time { return aggNow }), WithDistro(FamilyDebian))
}

func utmpRec(user, line, host string, ts time.Time) []byte {
	b := make([]byte, 384)
	binary.LittleEndian.PutUint16(b[0:], 6) // LOGIN_PROCESS
	copy(b[8:40], line)
	copy(b[44:76], user)
	copy(b[76:332], host)
	binary.LittleEndian.PutUint32(b[340:], uint32(ts.Unix()))
	return b
}

func TestBruteForce(t *testing.T) {
	var btmp []byte
	for i := range 6 { // 6 attempts from one host within 5 minutes
		btmp = append(btmp, utmpRec("root", "ssh:notty", "203.0.113.42", aggNow.Add(-time.Duration(i)*time.Minute))...)
	}
	btmp = append(btmp, utmpRec("admin", "ssh:notty", "198.51.100.7", aggNow)...) // lone attempt

	anoms := bruteForce(aggEnv(t, map[string][]byte{"var/log/btmp": btmp}))
	if len(anoms) != 1 {
		t.Fatalf("got %d anomalies, want 1", len(anoms))
	}
	if anoms[0].Severity != HealthCrit || !strings.Contains(anoms[0].Title, "203.0.113.42") {
		t.Errorf("anomaly = %+v", anoms[0])
	}
}

func TestRateSpike(t *testing.T) {
	var b strings.Builder
	for i := range 6 { // prior hour: low error rate
		ts := aggNow.Add(-time.Duration(20+i*5) * time.Minute)
		fmt.Fprintf(&b, "%s host app: ERROR steady\n", ts.Format("Jan _2 15:04:05"))
	}
	for i := range 10 { // last 10 minutes: spike
		ts := aggNow.Add(-time.Duration(i) * time.Minute)
		fmt.Fprintf(&b, "%s host app: ERROR burst\n", ts.Format("Jan _2 15:04:05"))
	}

	anoms := rateSpike(aggEnv(t, map[string][]byte{"var/log/syslog": []byte(b.String())}))
	if len(anoms) != 1 {
		t.Fatalf("got %d anomalies, want 1 spike", len(anoms))
	}
	if anoms[0].Severity != HealthCrit {
		t.Errorf("spike severity = %v, want CRIT", anoms[0].Severity)
	}
}

func TestRateSpikeSteadyIsQuiet(t *testing.T) {
	var b strings.Builder
	for i := range 12 { // even spread across the hour — no spike
		ts := aggNow.Add(-time.Duration(i*5) * time.Minute)
		fmt.Fprintf(&b, "%s host app: ERROR steady\n", ts.Format("Jan _2 15:04:05"))
	}
	if anoms := rateSpike(aggEnv(t, map[string][]byte{"var/log/syslog": []byte(b.String())})); len(anoms) != 0 {
		t.Errorf("steady rate flagged %d spikes, want 0", len(anoms))
	}
}

func TestParseSyslogTimeISOUsesLocalZone(t *testing.T) {
	// On a +08:00 host, a zoneless ISO line must be read in local time, so a
	// line 5 minutes ago is 5 minutes ago — not 8h in the future.
	loc := time.FixedZone("TST", 8*3600)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, loc)
	ts, ok := parseSyslogTime("2026-07-03T11:55:00 host app: ERROR boom", now)
	if !ok {
		t.Fatal("should parse an ISO timestamp")
	}
	if d := now.Sub(ts); d < 0 || d > 10*time.Minute {
		t.Errorf("age = %v, want ~5m (parsed in local zone)", d)
	}
}

func TestParseSyslogTimeZoneAwareISO(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	ts, ok := parseSyslogTime("2026-07-03T20:00:00+08:00 host app: ERROR", now)
	if !ok {
		t.Fatal("should parse an RFC3339 timestamp")
	}
	if !ts.Equal(now) { // 20:00+08:00 == 12:00Z == now
		t.Errorf("parsed %v, want it equal to %v", ts, now)
	}
}

func TestParseSyslogTimeYearBoundary(t *testing.T) {
	// Just after midnight on Jan 1: a "Dec 31 23:55" line belongs to last year.
	now := time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC)
	ts, ok := parseSyslogTime("Dec 31 23:55:00 host app: ERROR", now)
	if !ok {
		t.Fatal("should parse an RFC3164 timestamp")
	}
	if d := now.Sub(ts); d < 0 || d > 20*time.Minute {
		t.Errorf("age = %v, want ~10m (previous year), not ~a year in the future", d)
	}
}

func TestMaxInWindow(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	times := []time.Time{
		base, base.Add(time.Minute), base.Add(2 * time.Minute), base.Add(30 * time.Minute),
	}
	if got := maxInWindow(times, 5*time.Minute); got != 3 {
		t.Errorf("maxInWindow = %d, want 3", got)
	}
	if got := maxInWindow(nil, time.Minute); got != 0 {
		t.Errorf("maxInWindow(nil) = %d, want 0", got)
	}
}
