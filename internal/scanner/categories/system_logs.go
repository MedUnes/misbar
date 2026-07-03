package categories

import (
	"context"
	"fmt"

	"github.com/medunes/misbar/internal/scanner"
)

// systemLogs implements the category-1 scanner: syslog/kernel/auth/boot logs and
// the package log. Streaming (live tail) is attached in M3; the Scan funcs here
// capture the static snapshot.
type systemLogs struct{}

// SystemLogs returns the category-1 scanner.
func SystemLogs() scanner.Scanner { return systemLogs{} }

func (systemLogs) Meta() scanner.CategoryMeta {
	return scanner.CategoryMeta{ID: scanner.CatSystemLogs, Label: "System Logs"}
}

func (systemLogs) Artifacts(env *scanner.Env) []scanner.Artifact {
	cat := scanner.CatSystemLogs
	syslog, authlog, pkglog := env.SyslogPath(), env.AuthLogPath(), env.PkgLogPath()
	kern := env.Path("/var/log/kern.log")
	return []scanner.Artifact{
		{ID: "syslog", Category: cat, Label: syslog, Mode: scanner.ModeLive,
			Live: &scanner.LiveSource{Path: syslog}, Scan: logArtifact("syslog", cat, syslog)},
		{ID: "kern.log", Category: cat, Label: kern, Mode: scanner.ModeLive, Distros: scanner.DistroSet(scanner.FamilyDebian),
			Live: &scanner.LiveSource{Path: kern}, Scan: logArtifact("kern.log", cat, kern)},
		{ID: "auth.log", Category: cat, Label: authlog, Mode: scanner.ModeLive,
			Live: &scanner.LiveSource{Path: authlog}, Scan: logArtifact("auth.log", cat, authlog)},
		{ID: "dmesg", Category: cat, Label: "dmesg", Scan: scanDmesg},
		{ID: "journal", Category: cat, Label: "journalctl", Scan: scanJournal},
		{ID: "boot.log", Category: cat, Label: env.Path("/var/log/boot.log"), Scan: logArtifact("boot.log", cat, env.Path("/var/log/boot.log"))},
		{ID: "pkglog", Category: cat, Label: pkglog, Scan: logArtifact("pkglog", cat, pkglog)},
		{ID: "installer", Category: cat, Label: "/var/log/installer/", Scan: scanDirRecent("installer", cat, "/var/log/installer", scanner.RecentWindow7d, "installer log")},
	}
}

// logArtifact wraps logSnapshot for a fixed, already-resolved path.
func logArtifact(id scanner.ArtifactID, cat scanner.CategoryID, path string) scanFunc {
	return func(context.Context, *scanner.Env) scanner.ScanResult {
		return logSnapshot(id, cat, path)
	}
}

// scanDmesg captures `dmesg --level=err,warn`.
func scanDmesg(ctx context.Context, env *scanner.Env) scanner.ScanResult {
	res := cmdSnapshot(ctx, env, "dmesg", scanner.CatSystemLogs, "dmesg", "--level=err,warn")
	if res.Err != nil {
		return res
	}
	n := len(scanner.NonEmptyLines(res.Content.Text))
	res.Summary = fmt.Sprintf("%d err/warn line%s", n, plural(n, "", "s"))
	if n > 0 {
		res.Health = scanner.HealthWarn
	}
	return res
}

// scanJournal captures high-priority journal entries within the anomaly window.
func scanJournal(ctx context.Context, env *scanner.Env) scanner.ScanResult {
	since := env.Now().Add(-env.Since).Format("2006-01-02 15:04:05")
	res := cmdSnapshot(ctx, env, "journal", scanner.CatSystemLogs,
		"journalctl", "-p", "err..emerg", "--since", since, "--no-pager")
	if res.Err != nil {
		return res
	}
	n := len(scanner.NonEmptyLines(res.Content.Text))
	res.Summary = fmt.Sprintf("%d priority entr%s", n, plural(n, "y", "ies"))
	if n > 0 {
		res.Health = scanner.HealthWarn
	}
	return res
}
