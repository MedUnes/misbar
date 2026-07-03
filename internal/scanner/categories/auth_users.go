package categories

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/medunes/misbar/internal/fsutil"
	"github.com/medunes/misbar/internal/parser"
	"github.com/medunes/misbar/internal/scanner"
)

// authUsers implements the category-3 scanner: accounts, credentials, sudo
// rights, and login history.
type authUsers struct{}

// AuthUsers returns the category-3 scanner.
func AuthUsers() scanner.Scanner { return authUsers{} }

func (authUsers) Meta() scanner.CategoryMeta {
	return scanner.CategoryMeta{ID: scanner.CatAuthUsers, Label: "Auth & Users"}
}

func (authUsers) Artifacts(*scanner.Env) []scanner.Artifact {
	cat := scanner.CatAuthUsers
	return []scanner.Artifact{
		{ID: "passwd", Category: cat, Label: "/etc/passwd", Scan: scanPasswd},
		{ID: "shadow", Category: cat, Label: "/etc/shadow", NeedsRoot: true, Scan: scanShadow},
		{ID: "group", Category: cat, Label: "/etc/group", Scan: scanGroup},
		{ID: "sudoers", Category: cat, Label: "/etc/sudoers", Scan: scanSudoers},
		{ID: "sudoers.d", Category: cat, Label: "/etc/sudoers.d/", Scan: scanSudoersD},
		{ID: "ssh-keys", Category: cat, Label: "~/.ssh/authorized_keys", Scan: scanSSHKeys},
		{ID: "bash_history", Category: cat, Label: "~/.bash_history", Scan: scanUserFiles("bash_history", ".bash_history", scanner.HistoryPatterns, "suspicious command")},
		{ID: "bashrc", Category: cat, Label: "~/.bashrc", Scan: scanUserFiles("bashrc", ".bashrc", scanner.HistoryPatterns, "suspicious line")},
		{ID: "profile", Category: cat, Label: "~/.profile", Scan: scanUserFiles("profile", ".profile", scanner.HistoryPatterns, "suspicious line")},
		{ID: "bash_logout", Category: cat, Label: "~/.bash_logout", Scan: scanUserFiles("bash_logout", ".bash_logout", nil, "")},
		{ID: "recently-used", Category: cat, Label: "~/recently-used.xbel", Scan: scanUserFiles("recently-used", ".local/share/recently-used.xbel", nil, "")},
		{ID: "wtmp", Category: cat, Label: "/var/log/wtmp", Scan: scanWtmp},
		{ID: "btmp", Category: cat, Label: "/var/log/btmp", NeedsRoot: true, Scan: scanBtmp},
		{ID: "faillog", Category: cat, Label: "/var/log/faillog", Scan: presenceOnly("faillog", cat, "/var/log/faillog", true)},
		{ID: "lastlog", Category: cat, Label: "/var/log/lastlog", Scan: presenceOnly("lastlog", cat, "/var/log/lastlog", true)},
	}
}

// passwdEntry is one parsed /etc/passwd row (fields we care about).
type passwdEntry struct {
	Name  string
	UID   int
	Home  string
	Shell string
}

// parsePasswd parses passwd-format text into entries, skipping comments and
// malformed rows.
func parsePasswd(text string) []passwdEntry {
	var out []passwdEntry
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		out = append(out, passwdEntry{Name: f[0], UID: uid, Home: f[5], Shell: f[6]})
	}
	return out
}

// homeDirs returns the human users (home under /home or /root) from /etc/passwd,
// used to iterate per-user artifacts.
func homeDirs(env *scanner.Env) []passwdEntry {
	data, _, err := fsutil.ReadFileBounded(env.Path("/etc/passwd"), maxContentBytes)
	if err != nil {
		return nil
	}
	var out []passwdEntry
	for _, e := range parsePasswd(string(data)) {
		if e.Home == "/root" || strings.HasPrefix(e.Home, "/home/") {
			out = append(out, e)
		}
	}
	return out
}

// scanPasswd flags any UID-0 account other than root (instant privilege).
func scanPasswd(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := fileResult("passwd", scanner.CatAuthUsers, env.Path("/etc/passwd"))
	if res.Err != nil {
		setAbsent(&res)
		return res
	}

	entries := parsePasswd(res.Content.Text)
	var rogue []string
	for _, e := range entries {
		if e.UID == 0 && e.Name != "root" {
			rogue = append(rogue, fmt.Sprintf("%s (uid 0, shell %s)", e.Name, e.Shell))
		}
	}

	res.Health = scanner.HealthOK
	res.Summary = fmt.Sprintf("%d user%s", len(entries), plural(len(entries), "", "s"))
	if len(rogue) > 0 {
		res.Health = scanner.HealthCrit
		res.Summary = fmt.Sprintf("%d users, %d rogue UID-0", len(entries), len(rogue))
		res.Anomalies = append(res.Anomalies, scanner.Anomaly{
			Severity: scanner.HealthCrit,
			Title:    "non-root account with UID 0",
			Detail:   "Accounts other than root with UID 0 hold full root privileges.",
			Evidence: rogue,
			Artifact: "passwd",
		})
	}
	return res
}

// scanShadow flags accounts with an empty password hash and redacts hashes in
// the captured content.
func scanShadow(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := fileResult("shadow", scanner.CatAuthUsers, env.Path("/etc/shadow"))
	if res.Err != nil {
		setAbsent(&res)
		return res
	}

	var empty []string
	for _, line := range scanner.NonEmptyLines(res.Content.Text) {
		f := strings.Split(line, ":")
		if len(f) < 2 {
			continue
		}
		if f[1] == "" {
			empty = append(empty, f[0])
		}
	}

	res.Health = scanner.HealthOK
	res.Summary = "no empty password hashes"
	if len(empty) > 0 {
		res.Health = scanner.HealthCrit
		res.Summary = fmt.Sprintf("%d empty password hash%s", len(empty), plural(len(empty), "", "es"))
		res.Anomalies = append(res.Anomalies, scanner.Anomaly{
			Severity: scanner.HealthCrit,
			Title:    "account with empty password hash",
			Detail:   "These accounts can authenticate with no password: " + strings.Join(empty, ", "),
			Evidence: empty,
			Artifact: "shadow",
		})
	}
	res.Content.Text = redactShadow(res.Content.Text)
	return res
}

// redactShadow blanks the hash field so credentials never reach the viewer.
func redactShadow(text string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(text, "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 2 && f[1] != "" && f[1] != "*" && f[1] != "!" {
			f[1] = "***redacted***"
		}
		b.WriteString(strings.Join(f, ":"))
		b.WriteByte('\n')
	}
	return b.String()
}

// scanGroup flags populated privileged groups (sudo/wheel/adm/admin).
func scanGroup(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := fileResult("group", scanner.CatAuthUsers, env.Path("/etc/group"))
	if res.Err != nil {
		setAbsent(&res)
		return res
	}

	privileged := map[string]bool{"sudo": true, "wheel": true, "adm": true, "admin": true}
	var flagged []string
	for _, line := range scanner.NonEmptyLines(res.Content.Text) {
		f := strings.Split(line, ":")
		if len(f) < 4 || !privileged[f[0]] {
			continue
		}
		if members := strings.TrimSpace(f[3]); members != "" {
			flagged = append(flagged, f[0]+": "+members)
		}
	}

	res.Health = scanner.HealthOK
	res.Summary = "no privileged extras"
	if len(flagged) > 0 {
		res.Health = scanner.HealthWarn
		res.Summary = fmt.Sprintf("%d privileged group%s populated", len(flagged), plural(len(flagged), "", "s"))
		res.Anomalies = append(res.Anomalies, scanner.Anomaly{
			Severity: scanner.HealthWarn,
			Title:    "privileged group membership",
			Detail:   "Members of sudo/wheel/adm can escalate to root.",
			Evidence: flagged,
			Artifact: "group",
		})
	}
	return res
}

// scanSudoers flags NOPASSWD entries in the main sudoers file.
func scanSudoers(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := fileResult("sudoers", scanner.CatAuthUsers, env.Path("/etc/sudoers"))
	if res.Err != nil {
		setAbsent(&res)
		return res
	}
	if n := applyPatterns(&res, scanner.SudoersPatterns); n > 0 {
		res.Summary = fmt.Sprintf("%d NOPASSWD entr%s", n, plural(n, "y", "ies"))
	} else {
		res.Health = scanner.HealthOK
		res.Summary = "no NOPASSWD entries"
	}
	return res
}

// scanSudoersD aggregates NOPASSWD entries across the /etc/sudoers.d drop-ins.
func scanSudoersD(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := scanner.ScanResult{Category: scanner.CatAuthUsers, Artifact: "sudoers.d", Health: scanner.HealthSkip}
	entries, err := fsutil.ListDir(env.Path("/etc/sudoers.d"))
	if err != nil {
		_, locked := scanner.Classify(err)
		res.Locked = locked
		res.Err = err
		res.Summary = presenceSummary(scanner.HealthSkip, locked)
		return res
	}

	var content strings.Builder
	files, nopass := 0, 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, _, rerr := fsutil.ReadFileBounded(env.Path(filepath.Join("/etc/sudoers.d", e.Name())), maxContentBytes)
		if rerr != nil {
			continue
		}
		files++
		fmt.Fprintf(&content, "── %s ──\n%s\n\n", e.Name(), string(data))
		for _, a := range scanner.ScanLines(string(data), "sudoers.d", scanner.SudoersPatterns) {
			a.Detail = e.Name() + ": " + a.Detail
			res.Anomalies = append(res.Anomalies, a)
			res.Health = max(res.Health, a.Severity)
			nopass++
		}
	}

	if files == 0 {
		res.Summary = "empty"
		return res
	}
	res.Content = scanner.Content{Text: content.String()}
	if res.Health < scanner.HealthWarn {
		res.Health = scanner.HealthOK
	}
	if nopass > 0 {
		res.Summary = fmt.Sprintf("%d file%s, %d NOPASSWD", files, plural(files, "", "s"), nopass)
	} else {
		res.Summary = fmt.Sprintf("%d file%s, clean", files, plural(files, "", "s"))
	}
	return res
}

// scanSSHKeys lists authorized_keys per user and flags command= restrictions
// and recently modified key files.
func scanSSHKeys(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := scanner.ScanResult{Category: scanner.CatAuthUsers, Artifact: "ssh-keys", Health: scanner.HealthSkip}
	now := env.Now()

	var content strings.Builder
	totalKeys, usersWithKeys := 0, 0
	var recent []string
	for _, u := range homeDirs(env) {
		path := env.Path(filepath.Join(u.Home, ".ssh/authorized_keys"))
		data, _, err := fsutil.ReadFileBounded(path, maxContentBytes)
		if err != nil {
			continue
		}
		usersWithKeys++
		fmt.Fprintf(&content, "── %s (%s) ──\n", u.Name, path)
		for _, k := range scanner.NonEmptyLines(string(data)) {
			if strings.HasPrefix(k, "#") {
				continue
			}
			totalKeys++
			fmt.Fprintln(&content, sshKeyDigest(k))
			if strings.Contains(k, "command=") {
				res.Health = max(res.Health, scanner.HealthWarn)
				res.Anomalies = append(res.Anomalies, scanner.Anomaly{
					Severity: scanner.HealthWarn,
					Title:    "authorized_keys with command= restriction",
					Detail:   u.Name + ": " + truncate(k, 80),
					Evidence: []string{k},
					Artifact: "ssh-keys",
				})
			}
		}
		content.WriteByte('\n')
		if info, serr := fsutil.StatInfo(path); serr == nil && scanner.RecentlyModified(info, scanner.RecentWindow, now) {
			recent = append(recent, u.Name)
		}
	}

	if usersWithKeys == 0 {
		res.Summary = "no authorized_keys"
		return res
	}
	res.Content = scanner.Content{Text: content.String()}
	if res.Health < scanner.HealthWarn {
		res.Health = scanner.HealthOK
	}
	if len(recent) > 0 {
		res.Health = max(res.Health, scanner.HealthWarn)
		res.Anomalies = append(res.Anomalies, scanner.Anomaly{
			Severity: scanner.HealthWarn,
			Title:    "recently modified authorized_keys",
			Detail:   "Modified within 24h for: " + strings.Join(recent, ", "),
			Evidence: recent,
			Artifact: "ssh-keys",
		})
	}
	res.Summary = fmt.Sprintf("%d key%s across %d user%s", totalKeys, plural(totalKeys, "", "s"), usersWithKeys, plural(usersWithKeys, "", "s"))
	return res
}

// sshKeyDigest renders an authorized_keys line as "type … comment", hiding the
// long base64 blob.
func sshKeyDigest(k string) string {
	fields := strings.Fields(k)
	for i, f := range fields {
		if strings.HasPrefix(f, "ssh-") || strings.HasPrefix(f, "ecdsa-") || strings.HasPrefix(f, "sk-") {
			comment := ""
			if i+2 < len(fields) {
				comment = strings.Join(fields[i+2:], " ")
			}
			return strings.TrimSpace(f + " … " + comment)
		}
	}
	return truncate(k, 80)
}

// scanUserFiles reads relPath under each user's home, runs the optional line
// patterns, and aggregates matches with per-user attribution. When patterns is
// nil it merely records presence and content.
func scanUserFiles(id scanner.ArtifactID, relPath string, patterns []scanner.LinePattern, noun string) scanFunc {
	return func(_ context.Context, env *scanner.Env) scanner.ScanResult {
		res := scanner.ScanResult{Category: scanner.CatAuthUsers, Artifact: id, Health: scanner.HealthSkip}
		var content strings.Builder
		found := 0
		for _, u := range homeDirs(env) {
			path := env.Path(filepath.Join(u.Home, relPath))
			data, _, err := fsutil.ReadFileBounded(path, maxContentBytes)
			if err != nil {
				continue
			}
			found++
			fmt.Fprintf(&content, "── %s (%s) ──\n%s\n\n", u.Name, path, string(data))
			for _, a := range scanner.ScanLines(string(data), id, patterns) {
				a.Detail = u.Name + ": " + a.Detail
				res.Anomalies = append(res.Anomalies, a)
				res.Health = max(res.Health, a.Severity)
			}
		}

		if found == 0 {
			res.Summary = "none found"
			return res
		}
		res.Content = scanner.Content{Text: content.String()}
		if res.Health < scanner.HealthWarn {
			res.Health = scanner.HealthOK
		}
		if len(res.Anomalies) > 0 {
			res.Summary = fmt.Sprintf("%d %s across %d user%s", len(res.Anomalies), noun, found, plural(found, "", "s"))
		} else {
			res.Summary = fmt.Sprintf("%d user%s, clean", found, plural(found, "", "s"))
		}
		return res
	}
}

// scanWtmp parses /var/log/wtmp into recent login sessions (the `last` view).
func scanWtmp(_ context.Context, env *scanner.Env) scanner.ScanResult {
	return scanUtmp("wtmp", env.Path("/var/log/wtmp"), func(entries []parser.UtmpEntry) (scanner.Health, string) {
		n := len(parser.Sessions(entries))
		return scanner.HealthOK, fmt.Sprintf("%d login session%s", n, plural(n, "", "s"))
	}, parser.Sessions)
}

// scanBtmp parses /var/log/btmp into failed login attempts (the `lastb` view),
// warning when there are many.
func scanBtmp(_ context.Context, env *scanner.Env) scanner.ScanResult {
	return scanUtmp("btmp", env.Path("/var/log/btmp"), func(entries []parser.UtmpEntry) (scanner.Health, string) {
		n := len(parser.FailedLogins(entries))
		h := scanner.HealthOK
		if n >= 5 {
			h = scanner.HealthWarn
		}
		return h, fmt.Sprintf("%d failed attempt%s", n, plural(n, "", "s"))
	}, parser.FailedLogins)
}

// scanUtmp is the shared wtmp/btmp scan: parse, classify errors, summarize, and
// render the selected view into content.
func scanUtmp(id scanner.ArtifactID, path string, summarize func([]parser.UtmpEntry) (scanner.Health, string), view func([]parser.UtmpEntry) []parser.UtmpEntry) scanner.ScanResult {
	res := scanner.ScanResult{Category: scanner.CatAuthUsers, Artifact: id}
	entries, err := parser.ParseUtmpFile(path)
	if err != nil {
		health, locked := scanner.Classify(err)
		res.Health, res.Locked, res.Err = health, locked, err
		res.Summary = presenceSummary(health, locked)
		return res
	}
	res.Health, res.Summary = summarize(entries)
	res.Content = scanner.Content{Text: formatSessions(view(entries)), Binary: true}
	return res
}

// formatSessions renders login records most-recent-first as an aligned table.
func formatSessions(sessions []parser.UtmpEntry) string {
	var b strings.Builder
	for i := len(sessions) - 1; i >= 0; i-- {
		s := sessions[i]
		fmt.Fprintf(&b, "%-16s %-12s %-22s %s\n",
			s.User, s.Line, s.Host, s.Time.Format("2006-01-02 15:04:05"))
	}
	return b.String()
}
