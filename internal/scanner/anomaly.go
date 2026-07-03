package scanner

import (
	"os"
	"regexp"
	"strings"
	"time"
)

// Recency windows for "recently modified" structural checks (per spec).
const (
	RecentWindow   = 24 * time.Hour     // profile.d, usr/local/bin, sensitive dirs
	RecentWindow7d = 7 * 24 * time.Hour // init.d scripts, systemd units
)

// LinePattern flags any line of an artifact's text that matches Re. It is the
// regex half of the anomaly engine; structural checks live in the scan funcs.
type LinePattern struct {
	Re       *regexp.Regexp
	Severity Health
	Title    string
}

// ScanLines runs patterns over text and returns one Anomaly per matching line.
// Blank lines are skipped so evidence stays meaningful.
func ScanLines(text string, art ArtifactID, patterns []LinePattern) []Anomaly {
	var out []Anomaly
	lines := strings.Split(text, "\n")
	for _, p := range patterns {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if p.Re.MatchString(line) {
				out = append(out, Anomaly{
					Severity: p.Severity,
					Title:    p.Title,
					Detail:   trimmed,
					Evidence: []string{trimmed},
					Artifact: art,
				})
			}
		}
	}
	return out
}

// HistoryPatterns flags suspicious shell-history commands (spec category 3).
var HistoryPatterns = []LinePattern{
	{Re: regexp.MustCompile(`(?i)\b(curl|wget)\b.*\|\s*(bash|sh|zsh)\b`), Severity: HealthCrit, Title: "pipe-to-shell download"},
	{Re: regexp.MustCompile(`(?i)\bchmod\s+(\+x|[0-7]*[1357][0-7]*)\b`), Severity: HealthWarn, Title: "made a file executable"},
	{Re: regexp.MustCompile(`(?i)\b(nc|ncat|netcat)\b`), Severity: HealthWarn, Title: "netcat usage"},
	{Re: regexp.MustCompile(`(?i)\bbase64\b\s+(-d|--decode)\b`), Severity: HealthWarn, Title: "base64 decode"},
	{Re: regexp.MustCompile(`(?i)\bhistory\s+-c\b`), Severity: HealthCrit, Title: "shell history cleared"},
}

// SSHDPatterns flags risky sshd_config directives (spec category 5).
var SSHDPatterns = []LinePattern{
	{Re: regexp.MustCompile(`(?i)^\s*PermitRootLogin\s+yes\b`), Severity: HealthCrit, Title: "PermitRootLogin yes"},
	{Re: regexp.MustCompile(`(?i)^\s*PermitEmptyPasswords\s+yes\b`), Severity: HealthCrit, Title: "PermitEmptyPasswords yes"},
	{Re: regexp.MustCompile(`(?i)^\s*PasswordAuthentication\s+yes\b`), Severity: HealthWarn, Title: "PasswordAuthentication yes"},
}

// SudoersPatterns flags risky sudoers entries (spec category 3).
var SudoersPatterns = []LinePattern{
	{Re: regexp.MustCompile(`(?i)\bNOPASSWD\b`), Severity: HealthWarn, Title: "NOPASSWD sudoers entry"},
}

// RecentlyModified reports whether info's mtime falls within window before now.
// A future mtime (clock skew) is not treated as recent.
func RecentlyModified(info os.FileInfo, window time.Duration, now time.Time) bool {
	d := now.Sub(info.ModTime())
	return d >= 0 && d <= window
}

// NonEmptyLines returns the trimmed, non-blank lines of text — handy for
// attaching a small file's content as anomaly evidence.
func NonEmptyLines(text string) []string {
	var out []string
	for l := range strings.SplitSeq(text, "\n") {
		if s := strings.TrimSpace(l); s != "" {
			out = append(out, s)
		}
	}
	return out
}
