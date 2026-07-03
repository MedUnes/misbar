// Package categories holds the self-contained per-category scanners. Each file
// implements scanner.Scanner for one category and imports scanner for its types;
// categories never import one another. The registry (All) lives here rather than
// in scanner to avoid a scanner↔categories import cycle.
package categories

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/medunes/misbar/internal/fsutil"
	"github.com/medunes/misbar/internal/parser"
	"github.com/medunes/misbar/internal/scanner"
)

// maxContentBytes caps how much of any single artifact we hold in memory for
// the full-screen view. Large logs are truncated with a flag.
const maxContentBytes = 256 << 10 // 256 KiB

// All returns every category scanner in dashboard order. main and the TUI build
// an Orchestrator from this list.
func All() []scanner.Scanner {
	return []scanner.Scanner{
		SystemLogs(),
		Network(),
		AuthUsers(),
		Filesystem(),
		Persistence(),
		Services(),
		Toolbox(),
	}
}

// scanFunc is the signature of an artifact's Scan field.
type scanFunc = func(context.Context, *scanner.Env) scanner.ScanResult

// fileResult reads path, classifies the error, and returns a base result with
// content populated when readable. Callers layer findings/anomalies on top.
func fileResult(id scanner.ArtifactID, cat scanner.CategoryID, path string) scanner.ScanResult {
	data, truncated, err := fsutil.ReadFileBounded(path, maxContentBytes)
	health, locked := scanner.Classify(err)
	res := scanner.ScanResult{
		Category: cat,
		Artifact: id,
		Health:   health,
		Locked:   locked,
		Err:      err,
	}
	switch {
	case err == nil:
		res.Content = scanner.Content{Text: string(data), Truncated: truncated}
	case locked:
		res.Summary = "permission denied — run with sudo"
	default:
		res.Summary = "not present"
	}
	return res
}

// applyPatterns runs patterns over the result's content, appends any anomalies,
// and raises the result's health to the highest severity matched. Returns the
// number of matches.
func applyPatterns(res *scanner.ScanResult, patterns []scanner.LinePattern) int {
	anoms := scanner.ScanLines(res.Content.Text, res.Artifact, patterns)
	res.Anomalies = append(res.Anomalies, anoms...)
	for _, a := range anoms {
		res.Health = max(res.Health, a.Severity)
	}
	return len(anoms)
}

// simpleFile reads a file and reports only its presence and line count — used
// for artifacts we surface without deeper analysis (e.g. motd, at.allow).
func simpleFile(id scanner.ArtifactID, cat scanner.CategoryID, path string) scanFunc {
	return func(_ context.Context, env *scanner.Env) scanner.ScanResult {
		res := fileResult(id, cat, env.Path(path))
		if res.Err == nil {
			n := len(scanner.NonEmptyLines(res.Content.Text))
			res.Summary = fmt.Sprintf("%d line%s", n, plural(n, "", "s"))
		}
		return res
	}
}

// scanDirRecent lists a directory, records the listing as content, and flags
// entries modified within window as a WARN anomaly ("recently modified <kind>").
func scanDirRecent(id scanner.ArtifactID, cat scanner.CategoryID, path string, window time.Duration, kind string) scanFunc {
	return func(_ context.Context, env *scanner.Env) scanner.ScanResult {
		entries, err := fsutil.ListDir(env.Path(path))
		health, locked := scanner.Classify(err)
		res := scanner.ScanResult{Category: cat, Artifact: id, Health: health, Locked: locked, Err: err}
		if err != nil {
			if locked {
				res.Summary = "permission denied — run with sudo"
			} else {
				res.Summary = "not present"
			}
			return res
		}

		now := env.Now()
		names := make([]string, 0, len(entries))
		var recent []string
		for _, e := range entries {
			names = append(names, e.Name())
			if info, ierr := e.Info(); ierr == nil && scanner.RecentlyModified(info, window, now) {
				recent = append(recent, e.Name())
			}
		}
		slices.Sort(names)
		res.Content = scanner.Content{Text: strings.Join(names, "\n")}
		res.Health = scanner.HealthOK
		res.Summary = fmt.Sprintf("%d entr%s", len(names), plural(len(names), "y", "ies"))

		if len(recent) > 0 {
			slices.Sort(recent)
			res.Health = scanner.HealthWarn
			res.Summary = fmt.Sprintf("%d entries, %d recent", len(names), len(recent))
			res.Anomalies = append(res.Anomalies, scanner.Anomaly{
				Severity: scanner.HealthWarn,
				Title:    "recently modified " + kind,
				Detail:   fmt.Sprintf("Modified within %s: %s", humanDur(window), strings.Join(recent, ", ")),
				Evidence: recent,
				Artifact: id,
			})
		}
		return res
	}
}

// presenceOnly reports only that a file exists, its size, and mtime — used for
// binary artifacts whose full parser arrives in a later milestone (lastlog,
// faillog). binary flags the content as non-text for the viewer.
func presenceOnly(id scanner.ArtifactID, cat scanner.CategoryID, path string, binary bool) scanFunc {
	return func(_ context.Context, env *scanner.Env) scanner.ScanResult {
		info, err := fsutil.StatInfo(env.Path(path))
		health, locked := scanner.Classify(err)
		res := scanner.ScanResult{Category: cat, Artifact: id, Health: health, Locked: locked, Err: err}
		if err != nil {
			res.Summary = presenceSummary(health, locked)
			return res
		}
		res.Health = scanner.HealthOK
		res.Summary = fmt.Sprintf("present, %d bytes, modified %s", info.Size(), info.ModTime().Format("2006-01-02 15:04"))
		res.Content = scanner.Content{Text: res.Summary, Binary: binary}
		return res
	}
}

// logSnapshot reads the tail of a log file, classifies each line's severity,
// and summarizes the error/warning bands. Health is the worst band seen (crit
// for emerg/alert/crit lines, warn for errors/warnings).
func logSnapshot(id scanner.ArtifactID, cat scanner.CategoryID, path string) scanner.ScanResult {
	data, truncated, err := fsutil.ReadFileTail(path, maxContentBytes)
	health, locked := scanner.Classify(err)
	res := scanner.ScanResult{Category: cat, Artifact: id, Health: health, Locked: locked, Err: err}
	if err != nil {
		res.Summary = presenceSummary(health, locked)
		return res
	}
	res.Content = scanner.Content{Text: string(data), Truncated: truncated}

	crit, errs, warns := 0, 0, 0
	worst := scanner.HealthOK
	for _, line := range scanner.NonEmptyLines(string(data)) {
		switch sev := parser.ClassifyLine(line); {
		case sev <= parser.SevCrit:
			crit++
			worst = scanner.HealthCrit
		case sev == parser.SevErr:
			errs++
			worst = max(worst, scanner.HealthWarn)
		case sev.IsWarning():
			warns++
			worst = max(worst, scanner.HealthWarn)
		}
	}
	res.Health = worst
	res.Summary = summarizeSeverities(crit, errs, warns)
	return res
}

// summarizeSeverities formats the notable severity counts, or "clean".
func summarizeSeverities(crit, errs, warns int) string {
	var parts []string
	if crit > 0 {
		parts = append(parts, fmt.Sprintf("%d crit", crit))
	}
	if errs > 0 {
		parts = append(parts, fmt.Sprintf("%d err", errs))
	}
	if warns > 0 {
		parts = append(parts, fmt.Sprintf("%d warn", warns))
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, ", ")
}

// cmdSnapshot runs an allowlisted command and captures its output as content.
func cmdSnapshot(ctx context.Context, env *scanner.Env, id scanner.ArtifactID, cat scanner.CategoryID, name string, args ...string) scanner.ScanResult {
	res := scanner.ScanResult{Category: cat, Artifact: id, Health: scanner.HealthSkip}
	out, err := env.Cmd(ctx, name, args...)
	if err != nil {
		res.Err = err
		res.Summary = name + " unavailable"
		return res
	}
	res.Health = scanner.HealthOK
	res.Content = scanner.Content{Text: string(out)}
	return res
}

// presenceSummary is the one-line summary for an artifact we could not read.
func presenceSummary(health scanner.Health, locked bool) string {
	switch {
	case locked:
		return "permission denied — run with sudo"
	case health == scanner.HealthSkip:
		return "not present"
	default:
		return "unreadable"
	}
}

// setAbsent labels a benign missing (non-locked) file "absent".
func setAbsent(res *scanner.ScanResult) {
	if res.Health == scanner.HealthSkip && !res.Locked {
		res.Summary = "absent"
	}
}

// truncate shortens s to at most n runes, adding an ellipsis when cut. It cuts
// on rune boundaries so multi-byte UTF-8 characters are never split.
func truncate(s string, n int) string {
	if len(s) <= n { // fast path: byte length bounds rune count
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// plural picks the singular or plural suffix for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// humanDur renders a coarse duration like "24h" or "7d" for messages.
func humanDur(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	}
	return d.String()
}
