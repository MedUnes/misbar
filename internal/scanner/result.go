package scanner

import (
	"errors"
	"os"
	"time"
)

// Health is an artifact's (or category's) severity level. The ordering is
// deliberate: a category's health is max(artifact healths), and an all-Skip
// category collapses back to Skip because Skip is the zero value.
type Health uint8

const (
	HealthSkip Health = iota // file not found, or permission denied
	HealthOK                 // present, no anomalies
	HealthWarn               // warnings present, review recommended
	HealthCrit               // anomalies detected, immediate attention
)

// String returns the short uppercase label used in reports.
func (h Health) String() string {
	switch h {
	case HealthOK:
		return "OK"
	case HealthWarn:
		return "WARN"
	case HealthCrit:
		return "CRIT"
	default:
		return "SKIP"
	}
}

// Badge returns the spec's colored status emoji.
func (h Health) Badge() string {
	switch h {
	case HealthOK:
		return "🟢"
	case HealthWarn:
		return "🟡"
	case HealthCrit:
		return "🔴"
	default:
		return "⚪"
	}
}

// Classify maps a filesystem error to a Health and a locked flag. A missing
// file is a benign Skip; a permission error is a Skip that earns the 🔒 icon;
// anything else is a Warn worth surfacing.
func Classify(err error) (health Health, locked bool) {
	switch {
	case err == nil:
		return HealthOK, false
	case errors.Is(err, os.ErrNotExist):
		return HealthSkip, false
	case errors.Is(err, os.ErrPermission):
		return HealthSkip, true
	default:
		return HealthWarn, false
	}
}

// ScanResult is one artifact's outcome. Results arrive unordered and rescans
// replay them, so applying a result must be idempotent (keyed by Artifact).
type ScanResult struct {
	Category  CategoryID
	Artifact  ArtifactID
	Health    Health
	Summary   string // one-line summary for the panel/list
	Findings  []Finding
	Anomalies []Anomaly
	Content   Content // bounded raw text for the full-screen view
	Locked    bool    // permission denied → 🔒
	Err       error
	Elapsed   time.Duration
}

// Content is the bounded raw text captured for the full-screen artifact view.
type Content struct {
	Text      string
	Binary    bool
	Truncated bool
}

// Finding is a single noteworthy line-item within an artifact.
type Finding struct {
	Severity Health
	Message  string
}

// Anomaly is a detected red flag, richer than a Finding: it carries evidence
// lines and a human explanation for the analyst.
type Anomaly struct {
	Severity Health
	Title    string
	Detail   string
	Evidence []string
	Artifact ArtifactID
}
