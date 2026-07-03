// Package report renders scan results headlessly. Collect drains the same scan
// channel the TUI uses and runs the aggregate detectors, so --json and --report
// stay consistent with the interactive view. json.go and text.go format it.
package report

import (
	"context"
	"os"
	"os/user"
	"slices"
	"strings"

	"github.com/medunes/misbar/internal/scanner"
)

// Report is the headless, serialization-friendly view of a scan.
type Report struct {
	Host       string        `json:"host"`
	Access     string        `json:"access"`
	Distro     string        `json:"distro"`
	Generated  string        `json:"generated"` // RFC3339, stamped by the caller
	Categories []Category    `json:"categories"`
	Aggregate  []Anomaly     `json:"aggregate_anomalies"`
	Counts     SeverityCount `json:"counts"`
}

// Category is one category's results.
type Category struct {
	ID        int        `json:"id"`
	Label     string     `json:"label"`
	Health    string     `json:"health"`
	Artifacts []Artifact `json:"artifacts"`
}

// Artifact is one artifact's headless result.
type Artifact struct {
	ID        string    `json:"id"`
	Health    string    `json:"health"`
	Summary   string    `json:"summary,omitempty"`
	Locked    bool      `json:"locked,omitempty"`
	Error     string    `json:"error,omitempty"`
	Anomalies []Anomaly `json:"anomalies,omitempty"`
}

// Anomaly is a detected red flag.
type Anomaly struct {
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// SeverityCount tallies artifacts by health across the whole scan.
type SeverityCount struct {
	Crit int `json:"crit"`
	Warn int `json:"warn"`
	OK   int `json:"ok"`
	Skip int `json:"skip"`
}

// Collect drains orch's scan into a Report and appends the aggregate detectors'
// findings. Generated is left blank for the caller to stamp (keeping Collect
// deterministic and testable).
func Collect(ctx context.Context, orch *scanner.Orchestrator) Report {
	byCat := make(map[scanner.CategoryID][]scanner.ScanResult)
	for r := range orch.Scan(ctx) {
		byCat[r.Category] = append(byCat[r.Category], r)
	}

	rep := Report{
		Host:   hostname(),
		Access: accessLevel(),
		Distro: orch.Env().Distro.String(),
	}

	for _, meta := range scanner.AllCategoryMeta() {
		results := byCat[meta.ID]
		cat := Category{ID: int(meta.ID), Label: meta.Label, Health: categoryHealth(results).String()}
		for _, r := range results {
			rep.Counts.add(r.Health)
			cat.Artifacts = append(cat.Artifacts, toArtifact(r))
		}
		slices.SortFunc(cat.Artifacts, func(a, b Artifact) int {
			return strings.Compare(a.ID, b.ID)
		})
		rep.Categories = append(rep.Categories, cat)
	}

	for _, a := range scanner.AggregateAnomalies(orch.Env()) {
		rep.Aggregate = append(rep.Aggregate, toAnomaly(a))
	}
	return rep
}

func toArtifact(r scanner.ScanResult) Artifact {
	a := Artifact{
		ID:      string(r.Artifact),
		Health:  r.Health.String(),
		Summary: r.Summary,
		Locked:  r.Locked,
	}
	if r.Err != nil {
		a.Error = r.Err.Error()
	}
	for _, an := range r.Anomalies {
		a.Anomalies = append(a.Anomalies, toAnomaly(an))
	}
	return a
}

func toAnomaly(a scanner.Anomaly) Anomaly {
	return Anomaly{
		Severity: a.Severity.String(),
		Title:    a.Title,
		Detail:   a.Detail,
		Evidence: a.Evidence,
	}
}

// categoryHealth is max(artifact healths); an empty category is Skip.
func categoryHealth(results []scanner.ScanResult) scanner.Health {
	h := scanner.HealthSkip
	for _, r := range results {
		h = max(h, r.Health)
	}
	return h
}

func (c *SeverityCount) add(h scanner.Health) {
	switch h {
	case scanner.HealthCrit:
		c.Crit++
	case scanner.HealthWarn:
		c.Warn++
	case scanner.HealthOK:
		c.OK++
	default:
		c.Skip++
	}
}

func hostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

func accessLevel() string {
	if os.Geteuid() == 0 {
		return "root"
	}
	if u, err := user.Current(); err == nil {
		return "user:" + u.Username
	}
	return "user"
}
