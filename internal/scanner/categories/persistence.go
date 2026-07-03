package categories

import (
	"context"
	"fmt"
	"strings"

	"github.com/medunes/misbar/internal/scanner"
)

// persistence implements the category-5 scanner: boot/login/service persistence
// mechanisms — the highest-signal category for incident response.
type persistence struct{}

// Persistence returns the category-5 scanner.
func Persistence() scanner.Scanner { return persistence{} }

func (persistence) Meta() scanner.CategoryMeta {
	return scanner.CategoryMeta{ID: scanner.CatPersistence, Label: "Persistence"}
}

func (persistence) Artifacts(*scanner.Env) []scanner.Artifact {
	cat := scanner.CatPersistence
	return []scanner.Artifact{
		{ID: "ld.so.preload", Category: cat, Label: "/etc/ld.so.preload", Scan: scanLdSoPreload},
		{ID: "rc.local", Category: cat, Label: "/etc/rc.local", Scan: scanRCLocal},
		{ID: "sshd_config", Category: cat, Label: "/etc/ssh/sshd_config", Scan: scanSSHDConfig},
		{ID: "init.d", Category: cat, Label: "/etc/init.d/", Scan: scanDirRecent("init.d", cat, "/etc/init.d", scanner.RecentWindow7d, "init script")},
		{ID: "profile.d", Category: cat, Label: "/etc/profile.d/", Scan: scanDirRecent("profile.d", cat, "/etc/profile.d", scanner.RecentWindow, "profile script")},
		{ID: "systemd-system", Category: cat, Label: "/etc/systemd/system/", Scan: scanDirRecent("systemd-system", cat, "/etc/systemd/system", scanner.RecentWindow7d, "systemd unit")},
		{ID: "usr-local-bin", Category: cat, Label: "/usr/local/bin/", Scan: scanDirRecent("usr-local-bin", cat, "/usr/local/bin", scanner.RecentWindow, "local binary")},
		{ID: "lib-systemd", Category: cat, Label: "/lib/systemd/system/", Scan: scanDirRecent("lib-systemd", cat, "/lib/systemd/system", scanner.RecentWindow7d, "system unit")},
		{ID: "motd", Category: cat, Label: "/etc/motd", Scan: simpleFile("motd", cat, "/etc/motd")},
		{ID: "at.allow", Category: cat, Label: "/etc/at.allow", Scan: simpleFile("at.allow", cat, "/etc/at.allow")},
		{ID: "at.deny", Category: cat, Label: "/etc/at.deny", Scan: simpleFile("at.deny", cat, "/etc/at.deny")},
	}
}

// scanLdSoPreload is the single highest-confidence check in misbar: a non-empty
// /etc/ld.so.preload is a classic rootkit persistence mechanism → instant CRIT.
func scanLdSoPreload(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := fileResult("ld.so.preload", scanner.CatPersistence, env.Path("/etc/ld.so.preload"))
	if res.Err != nil {
		if res.Health == scanner.HealthSkip && !res.Locked {
			res.Summary = "absent (good)"
		}
		return res
	}

	lines := scanner.NonEmptyLines(res.Content.Text)
	if len(lines) == 0 {
		res.Health = scanner.HealthOK
		res.Summary = "empty (good)"
		return res
	}

	res.Health = scanner.HealthCrit
	res.Summary = fmt.Sprintf("NON-EMPTY — %d preload entr%s", len(lines), plural(len(lines), "y", "ies"))
	res.Anomalies = append(res.Anomalies, scanner.Anomaly{
		Severity: scanner.HealthCrit,
		Title:    "ld.so.preload is non-empty",
		Detail:   "Library preloading via /etc/ld.so.preload injects the listed objects into every dynamically-linked process — a classic rootkit technique.",
		Evidence: lines,
		Artifact: "ld.so.preload",
	})
	return res
}

// scanRCLocal flags a non-default /etc/rc.local (anything beyond comments, the
// shebang, and a bare `exit 0`).
func scanRCLocal(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := fileResult("rc.local", scanner.CatPersistence, env.Path("/etc/rc.local"))
	if res.Err != nil {
		if res.Health == scanner.HealthSkip && !res.Locked {
			res.Summary = "absent"
		}
		return res
	}

	var active []string
	for _, l := range scanner.NonEmptyLines(res.Content.Text) {
		if strings.HasPrefix(l, "#") || l == "exit 0" {
			continue
		}
		active = append(active, l)
	}
	if len(active) == 0 {
		res.Health = scanner.HealthOK
		res.Summary = "default (exit 0)"
		return res
	}

	res.Health = scanner.HealthWarn
	res.Summary = fmt.Sprintf("%d custom line%s", len(active), plural(len(active), "", "s"))
	res.Anomalies = append(res.Anomalies, scanner.Anomaly{
		Severity: scanner.HealthWarn,
		Title:    "non-default rc.local",
		Detail:   "rc.local runs at boot and should normally contain only `exit 0`.",
		Evidence: active,
		Artifact: "rc.local",
	})
	return res
}

// scanSSHDConfig flags risky sshd_config directives (PermitRootLogin yes, etc.).
func scanSSHDConfig(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := fileResult("sshd_config", scanner.CatPersistence, env.Path("/etc/ssh/sshd_config"))
	if res.Err != nil {
		if res.Health == scanner.HealthSkip && !res.Locked {
			res.Summary = "absent"
		}
		return res
	}

	if n := applyPatterns(&res, scanner.SSHDPatterns); n > 0 {
		res.Summary = fmt.Sprintf("%d risky directive%s", n, plural(n, "", "s"))
	} else {
		res.Health = scanner.HealthOK
		res.Summary = "no risky directives"
	}
	return res
}
