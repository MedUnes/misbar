package tui

import (
	"fmt"

	"github.com/medunes/misbar/internal/scanner"
)

// artifactRow is the skeleton entry for one artifact: its identity is known
// before any result arrives, so the drilldown list is stable and shows
// "scanning…" until the result fills it in.
type artifactRow struct {
	id        scanner.ArtifactID
	label     string
	needsRoot bool
}

// categoryState accumulates results for one category. apply is commutative and
// idempotent (keyed by ArtifactID) because results arrive unordered and a
// rescan simply replays them.
type categoryState struct {
	meta       scanner.CategoryMeta
	rows       []artifactRow
	byArt      map[scanner.ArtifactID]scanner.ScanResult
	aggregate  []scanner.Anomaly // cross-artifact anomalies (brute force, spikes)
	hasScanner bool              // a real category scanner is registered for this slot
}

func newCategoryState(meta scanner.CategoryMeta) *categoryState {
	return &categoryState{meta: meta, byArt: make(map[scanner.ArtifactID]scanner.ScanResult)}
}

// apply records (or replaces) one artifact's result.
func (c *categoryState) apply(r scanner.ScanResult) {
	c.byArt[r.Artifact] = r
}

// result returns the stored result for an artifact and whether it has arrived.
func (c *categoryState) result(id scanner.ArtifactID) (scanner.ScanResult, bool) {
	r, ok := c.byArt[id]
	return r, ok
}

// health is max(artifact healths and aggregate-anomaly severities); an empty or
// all-Skip category is Skip.
func (c *categoryState) health() scanner.Health {
	h := scanner.HealthSkip
	for _, r := range c.byArt {
		h = max(h, r.Health)
	}
	for _, a := range c.aggregate {
		h = max(h, a.Severity)
	}
	return h
}

// scanned reports how many of the category's artifacts have results so far.
func (c *categoryState) scanned() int { return len(c.byArt) }

// counts partitions the arrived artifacts into ok / permission-denied / other-skip.
func (c *categoryState) counts() (ok, locked, skip int) {
	for _, r := range c.byArt {
		switch {
		case r.Locked:
			locked++
		case r.Health == scanner.HealthOK:
			ok++
		case r.Health == scanner.HealthSkip:
			skip++
		}
	}
	return ok, locked, skip
}

// tally counts crit/warn across both artifact health and aggregate anomalies, so
// the panel summary agrees with the badge (which is max of the same set).
func (c *categoryState) tally() (crit, warn int) {
	for _, r := range c.byArt {
		switch r.Health {
		case scanner.HealthCrit:
			crit++
		case scanner.HealthWarn:
			warn++
		}
	}
	for _, a := range c.aggregate {
		switch a.Severity {
		case scanner.HealthCrit:
			crit++
		case scanner.HealthWarn:
			warn++
		}
	}
	return crit, warn
}

// topAnomaly returns the most severe anomaly across artifacts and aggregate
// detectors (first-seen wins ties), or nil when there are none.
func (c *categoryState) topAnomaly() *scanner.Anomaly {
	var best *scanner.Anomaly
	consider := func(a *scanner.Anomaly) {
		if best == nil || a.Severity > best.Severity {
			best = a
		}
	}
	for _, row := range c.rows {
		if r, ok := c.byArt[row.id]; ok {
			for i := range r.Anomalies {
				consider(&r.Anomalies[i])
			}
		}
	}
	for i := range c.aggregate {
		consider(&c.aggregate[i])
	}
	return best
}

// Summary is the aggregate one-liner shown under a panel's health badge.
func (c *categoryState) Summary() string {
	switch {
	case !c.hasScanner:
		return "pending"
	case c.scanned() == 0:
		return "scanning…"
	}
	crit, warn := c.tally()
	switch {
	case crit > 0 && warn > 0:
		return fmt.Sprintf("%d crit, %d warn", crit, warn)
	case crit > 0:
		return fmt.Sprintf("%d critical", crit)
	case warn > 0:
		return fmt.Sprintf("%d warning%s", warn, pluralS(warn))
	}
	// No crit/warn: report only genuinely-OK checks, and never hide that some
	// checks were permission-denied (they'd otherwise look like passing checks).
	ok, locked, _ := c.counts()
	if locked > 0 {
		return fmt.Sprintf("%d ok, %d denied", ok, locked)
	}
	return fmt.Sprintf("%d checks ok", ok)
}

// pluralS returns "s" unless n == 1.
func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
