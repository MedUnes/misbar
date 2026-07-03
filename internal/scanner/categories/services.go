package categories

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/medunes/misbar/internal/fsutil"
	"github.com/medunes/misbar/internal/scanner"
)

// services implements the category-6 scanner: application logs, browser
// profiles, mail spools, and cron jobs.
type services struct{}

// Services returns the category-6 scanner.
func Services() scanner.Scanner { return services{} }

func (services) Meta() scanner.CategoryMeta {
	return scanner.CategoryMeta{ID: scanner.CatServices, Label: "Services & Cron"}
}

func (services) Artifacts(env *scanner.Env) []scanner.Artifact {
	cat := scanner.CatServices
	apacheErr := filepath.Join(env.WebLogDir(), "error.log")
	mysqlErr := env.Path("/var/log/mysql/error.log")
	return []scanner.Artifact{
		{ID: "cron", Category: cat, Label: "cron jobs", Scan: scanCron},
		{ID: "browsers", Category: cat, Label: "browser profiles", Scan: scanBrowsers},
		{ID: "mail", Category: cat, Label: "/var/mail/", Scan: scanMail},
		{ID: "apache", Category: cat, Label: apacheErr, Mode: scanner.ModeLive,
			Live: &scanner.LiveSource{Path: apacheErr}, Scan: logArtifact("apache", cat, apacheErr)},
		{ID: "mysql", Category: cat, Label: mysqlErr, Mode: scanner.ModeLive,
			Live: &scanner.LiveSource{Path: mysqlErr}, Scan: logArtifact("mysql", cat, mysqlErr)},
	}
}

// cronSources are the standard system and per-user cron locations.
var cronSources = []string{
	"/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
	"/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs",
}

// scanCron aggregates every cron source, records the job list, and flags any
// recently-modified job.
func scanCron(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := scanner.ScanResult{Category: scanner.CatServices, Artifact: "cron", Health: scanner.HealthSkip}
	now := env.Now()

	var content strings.Builder
	var recent []string
	total := 0
	denied := false // a cron source was unreadable (permission denied)
	markDenied := func(err error) {
		if _, locked := scanner.Classify(err); locked {
			denied = true
		}
	}
	for _, src := range cronSources {
		info, err := fsutil.StatInfo(env.Path(src))
		if err != nil {
			markDenied(err)
			continue
		}
		if !info.IsDir() {
			total++
			fmt.Fprintln(&content, src)
			if scanner.RecentlyModified(info, scanner.RecentWindow, now) {
				recent = append(recent, src)
			}
			continue
		}
		entries, lerr := fsutil.ListDir(env.Path(src))
		if lerr != nil {
			markDenied(lerr)
			continue
		}
		for _, e := range entries {
			total++
			name := src + "/" + e.Name()
			fmt.Fprintln(&content, name)
			if ei, ierr := e.Info(); ierr == nil && scanner.RecentlyModified(ei, scanner.RecentWindow, now) {
				recent = append(recent, name)
			}
		}
	}

	res.Locked = denied
	if total == 0 {
		if denied {
			res.Summary = "cron unreadable — run with sudo"
		} else {
			res.Summary = "no cron jobs"
		}
		return res
	}
	res.Content = scanner.Content{Text: content.String()}
	res.Health = scanner.HealthOK
	res.Summary = fmt.Sprintf("%d cron source%s", total, plural(total, "", "s"))
	if denied {
		res.Summary += " (some denied)"
	}
	if len(recent) > 0 {
		res.Health = scanner.HealthWarn
		res.Summary = fmt.Sprintf("%d sources, %d recent", total, len(recent))
		res.Anomalies = append(res.Anomalies, scanner.Anomaly{
			Severity: scanner.HealthWarn,
			Title:    "recently modified cron job",
			Detail:   "Cron jobs changed within 24h: " + strings.Join(recent, ", "),
			Evidence: recent,
			Artifact: "cron",
		})
	}
	return res
}

// browserProfiles are the profile directories whose presence on a server is
// itself suspicious (GUI usage).
var browserProfiles = []string{".mozilla/firefox", ".config/google-chrome", ".config/chromium"}

// scanBrowsers flags the presence of desktop-browser profiles per user.
func scanBrowsers(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := scanner.ScanResult{Category: scanner.CatServices, Artifact: "browsers", Health: scanner.HealthOK}
	var found []string
	for _, u := range homeDirs(env) {
		for _, rel := range browserProfiles {
			if fsutil.FileExists(env.Path(filepath.Join(u.Home, rel))) {
				found = append(found, u.Name+": "+rel)
			}
		}
	}

	res.Summary = "no browser profiles"
	if len(found) > 0 {
		res.Health = scanner.HealthWarn
		res.Content = scanner.Content{Text: strings.Join(found, "\n")}
		res.Summary = fmt.Sprintf("%d browser profile%s", len(found), plural(len(found), "", "s"))
		res.Anomalies = append(res.Anomalies, scanner.Anomaly{
			Severity: scanner.HealthWarn,
			Title:    "desktop browser profile on a server",
			Detail:   "GUI browser usage on a server is unusual and worth explaining.",
			Evidence: found,
			Artifact: "browsers",
		})
	}
	return res
}

// scanMail lists users with a non-empty mail spool.
func scanMail(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := scanner.ScanResult{Category: scanner.CatServices, Artifact: "mail", Health: scanner.HealthSkip}
	entries, err := fsutil.ListDir(env.Path("/var/mail"))
	if err != nil {
		health, locked := scanner.Classify(err)
		res.Health, res.Locked, res.Err = health, locked, err
		res.Summary = presenceSummary(health, locked)
		return res
	}

	var withMail []string
	for _, e := range entries {
		if info, ierr := e.Info(); ierr == nil && info.Size() > 0 {
			withMail = append(withMail, fmt.Sprintf("%s (%d bytes)", e.Name(), info.Size()))
		}
	}
	res.Health = scanner.HealthOK
	res.Content = scanner.Content{Text: strings.Join(withMail, "\n")}
	res.Summary = fmt.Sprintf("%d user%s with mail", len(withMail), plural(len(withMail), "", "s"))
	return res
}
