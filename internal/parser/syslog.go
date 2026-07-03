package parser

import "regexp"

// Severity is a syslog priority level (RFC 5424 numeric order: lower = worse).
type Severity uint8

const (
	SevEmerg Severity = iota
	SevAlert
	SevCrit
	SevErr
	SevWarning
	SevNotice
	SevInfo
	SevDebug
)

// String returns the short uppercase label.
func (s Severity) String() string {
	switch s {
	case SevEmerg:
		return "EMERG"
	case SevAlert:
		return "ALERT"
	case SevCrit:
		return "CRIT"
	case SevErr:
		return "ERR"
	case SevWarning:
		return "WARN"
	case SevNotice:
		return "NOTICE"
	case SevDebug:
		return "DEBUG"
	default:
		return "INFO"
	}
}

// IsError reports the emerg..err band — the lines counted for spike detection.
func (s Severity) IsError() bool { return s <= SevErr }

// IsWarning reports the warning level.
func (s Severity) IsWarning() bool { return s == SevWarning }

// sevPatterns are checked in order; the first match wins, so the most severe
// keywords are listed first.
var sevPatterns = []struct {
	re  *regexp.Regexp
	sev Severity
}{
	{regexp.MustCompile(`(?i)\b(emerg|kernel panic|panic)\b`), SevEmerg},
	{regexp.MustCompile(`(?i)\balert\b`), SevAlert},
	{regexp.MustCompile(`(?i)(\bcrit(ical)?\b|oom-killer|out of memory|segfault|general protection|\bBUG:|\bOops)`), SevCrit},
	{regexp.MustCompile(`(?i)(\berror\b|\bfailed\b|\bfailure\b|\bfatal\b|\bdenied\b|\brefused\b|\bcannot\b)`), SevErr},
	{regexp.MustCompile(`(?i)\bwarn(ing)?\b`), SevWarning},
	{regexp.MustCompile(`(?i)\bnotice\b`), SevNotice},
	{regexp.MustCompile(`(?i)\bdebug\b`), SevDebug},
}

// ClassifyLine returns the severity implied by a log line's keywords, defaulting
// to SevInfo when nothing stands out.
func ClassifyLine(line string) Severity {
	for _, p := range sevPatterns {
		if p.re.MatchString(line) {
			return p.sev
		}
	}
	return SevInfo
}
