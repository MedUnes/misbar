package scanner

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/medunes/misbar/internal/fsutil"
	"github.com/medunes/misbar/internal/parser"
)

// Aggregate-detector tuning.
const (
	bruteForceThreshold = 5                // failed logins from one IP…
	bruteForceWindow    = 10 * time.Minute // …within this window → brute force
	spikeMinErrors      = 5                // ignore low-volume noise
	spikeFactor         = 3.0              // recent rate > factor × prior average
)

// AggregateAnomalies runs the cross-artifact detectors that can only be
// computed after the per-artifact scans complete. It is pure w.r.t. Env
// (re-reads btmp and syslog) and safe to call from headless or TUI paths.
func AggregateAnomalies(env *Env) []Anomaly {
	var out []Anomaly
	out = append(out, bruteForce(env)...)
	out = append(out, rateSpike(env)...)
	return out
}

// bruteForce flags any source host with bruteForceThreshold failed logins inside
// any bruteForceWindow, from /var/log/btmp.
func bruteForce(env *Env) []Anomaly {
	entries, err := parser.ParseUtmpFile(env.Path("/var/log/btmp"))
	if err != nil {
		return nil
	}

	byHost := make(map[string][]time.Time)
	for _, e := range parser.FailedLogins(entries) {
		if e.Host != "" {
			byHost[e.Host] = append(byHost[e.Host], e.Time)
		}
	}

	// Deterministic ordering of the output.
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)

	var out []Anomaly
	for _, host := range hosts {
		if n := maxInWindow(byHost[host], bruteForceWindow); n >= bruteForceThreshold {
			out = append(out, Anomaly{
				Severity: HealthCrit,
				Title:    fmt.Sprintf("brute force: %d failed logins from %s", n, host),
				Detail:   fmt.Sprintf("%d failed SSH/login attempts from %s within %s.", n, host, bruteForceWindow),
				Evidence: []string{host},
				Artifact: "btmp",
			})
		}
	}
	return out
}

// maxInWindow returns the largest number of timestamps falling inside any
// sliding window of the given width.
func maxInWindow(times []time.Time, window time.Duration) int {
	slices.SortFunc(times, func(a, b time.Time) int { return a.Compare(b) })
	best, j := 0, 0
	for i := range times {
		for times[i].Sub(times[j]) > window {
			j++
		}
		best = max(best, i-j+1)
	}
	return best
}

// rateSpike flags when the error rate in the last 10 minutes exceeds spikeFactor
// times the prior hour's per-10-minute average, using the system log's tail.
func rateSpike(env *Env) []Anomaly {
	data, _, err := fsutil.ReadFileTail(env.SyslogPath(), 512*1024)
	if err != nil {
		return nil
	}
	now := env.Now()

	recent, prior := 0, 0
	for line := range strings.SplitSeq(string(data), "\n") {
		ts, ok := parseSyslogTime(line, now)
		if !ok || !parser.ClassifyLine(line).IsError() {
			continue
		}
		switch age := now.Sub(ts); {
		case age >= 0 && age < 10*time.Minute:
			recent++
		case age >= 10*time.Minute && age < 70*time.Minute:
			prior++
		}
	}

	priorAvg := float64(prior) / 6.0 // per 10-minute bucket over the prior hour
	if recent >= spikeMinErrors && float64(recent) > spikeFactor*priorAvg {
		return []Anomaly{{
			Severity: HealthCrit,
			Title:    "error-rate spike in system log",
			Detail:   fmt.Sprintf("%d errors in the last 10min vs %.1f/10min prior-hour average.", recent, priorAvg),
			Artifact: "syslog",
		}}
	}
	return nil
}

// parseSyslogTime extracts a timestamp from a log line, handling the RFC3164
// "Jan _2 15:04:05" prefix (no year, no zone) and an ISO-8601 prefix.
func parseSyslogTime(line string, now time.Time) (time.Time, bool) {
	// RFC3164: anchor the yearless, zoneless stamp to the host's zone and the
	// current year, correcting the December→January rollover (a "Dec 31" line
	// seen just after midnight on Jan 1 would otherwise be dated ~a year ahead).
	if len(line) >= 15 {
		if t, err := time.Parse("Jan _2 15:04:05", line[:15]); err == nil {
			ts := time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
			if ts.Sub(now) > 24*time.Hour {
				ts = ts.AddDate(-1, 0, 0)
			}
			return ts, true
		}
	}
	// ISO-8601: the timestamp is the first whitespace-delimited token. Prefer a
	// zone-aware RFC3339 parse; otherwise interpret the zoneless wall-clock in
	// the host's local zone so it is comparable to env.Now().
	if first, _, ok := strings.Cut(line, " "); ok {
		if t, err := time.Parse(time.RFC3339, first); err == nil {
			return t, true
		}
	}
	if len(line) >= 19 {
		if t, err := time.ParseInLocation("2006-01-02T15:04:05", line[:19], now.Location()); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
