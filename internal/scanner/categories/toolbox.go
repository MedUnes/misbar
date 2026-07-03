package categories

import (
	"context"
	"slices"

	"github.com/medunes/misbar/internal/scanner"
)

// toolbox implements the category-7 scanner: availability of forensic tools,
// rendered as the dashboard footer (not a grid panel). Each tool becomes a
// Finding whose severity encodes availability (OK = present, Skip = missing).
type toolbox struct{}

// Toolbox returns the category-7 scanner.
func Toolbox() scanner.Scanner { return toolbox{} }

func (toolbox) Meta() scanner.CategoryMeta {
	return scanner.CategoryMeta{ID: scanner.CatToolbox, Label: "Toolbox"}
}

// forensicTool maps a display name to the executables that satisfy it (any one
// present means available).
type forensicTool struct {
	name   string
	probes []string
}

var forensicTools = []forensicTool{
	{"dd", []string{"dd"}},
	{"md5sum", []string{"md5sum"}},
	{"sha256sum", []string{"sha256sum"}},
	{"log2timeline", []string{"log2timeline", "log2timeline.py"}},
	{"plaso", []string{"psteal", "psteal.py", "log2timeline"}},
	{"sleuthkit", []string{"fls", "mmls"}},
	{"rekall", []string{"rekall"}},
	{"volatility", []string{"vol", "vol.py", "vol3", "volatility"}},
	{"foremost", []string{"foremost"}},
	{"autopsy", []string{"autopsy"}},
}

func (toolbox) Artifacts(*scanner.Env) []scanner.Artifact {
	return []scanner.Artifact{
		{ID: "tools", Category: scanner.CatToolbox, Label: "Forensic tools", Scan: scanTools},
	}
}

// scanTools probes each forensic tool via `which` and records availability.
func scanTools(ctx context.Context, env *scanner.Env) scanner.ScanResult {
	res := scanner.ScanResult{Category: scanner.CatToolbox, Artifact: "tools", Health: scanner.HealthOK}
	for _, t := range forensicTools {
		available := slices.ContainsFunc(t.probes, func(p string) bool {
			return env.HasCommand(ctx, p)
		})
		sev := scanner.HealthSkip
		if available {
			sev = scanner.HealthOK
		}
		res.Findings = append(res.Findings, scanner.Finding{Severity: sev, Message: t.name})
	}
	return res
}
