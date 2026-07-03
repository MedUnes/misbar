package scanner

import (
	"bufio"
	"os"
	"strings"

	"github.com/medunes/misbar/internal/fsutil"
)

// DetectDistro determines the package/log-layout family. It first parses
// /etc/os-release (ID, ID_LIKE); if that is inconclusive it falls back to
// which family-specific log files exist. Defaults to Debian when unknown, since
// that layout is the more common Ubuntu/Debian case for the tool's audience.
func DetectDistro(e *Env) DistroFamily {
	if f := familyFromOSRelease(e.Path("/etc/os-release")); f != 0 {
		return f
	}
	// Fallback: presence of layout-defining files.
	switch {
	case fsutil.FileExists(e.Path("/var/log/secure")), fsutil.FileExists(e.Path("/var/log/messages")):
		return FamilyRHEL
	case fsutil.FileExists(e.Path("/var/log/auth.log")), fsutil.FileExists(e.Path("/var/log/syslog")):
		return FamilyDebian
	default:
		return FamilyDebian
	}
}

// familyFromOSRelease maps os-release ID/ID_LIKE tokens to a family, or 0.
func familyFromOSRelease(path string) DistroFamily {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	tokens := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key != "ID" && key != "ID_LIKE" {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		for tok := range strings.FieldsSeq(val) {
			tokens[strings.ToLower(tok)] = true
		}
	}
	if sc.Err() != nil {
		return 0 // unreadable mid-file → let the caller fall back
	}

	for _, t := range []string{"rhel", "fedora", "centos", "rocky", "almalinux", "amzn"} {
		if tokens[t] {
			return FamilyRHEL
		}
	}
	for _, t := range []string{"debian", "ubuntu"} {
		if tokens[t] {
			return FamilyDebian
		}
	}
	return 0
}

// AuthLogPath returns the auth log path for the detected family.
func (e *Env) AuthLogPath() string {
	if e.Distro == FamilyRHEL {
		return e.Path("/var/log/secure")
	}
	return e.Path("/var/log/auth.log")
}

// SyslogPath returns the primary system log path for the detected family.
func (e *Env) SyslogPath() string {
	if e.Distro == FamilyRHEL {
		return e.Path("/var/log/messages")
	}
	return e.Path("/var/log/syslog")
}

// PkgLogPath returns the package-manager log path for the detected family.
func (e *Env) PkgLogPath() string {
	if e.Distro == FamilyRHEL {
		return e.Path("/var/log/yum.log")
	}
	return e.Path("/var/log/dpkg.log")
}

// WebLogDir returns the Apache/httpd log directory for the detected family.
func (e *Env) WebLogDir() string {
	if e.Distro == FamilyRHEL {
		return e.Path("/var/log/httpd")
	}
	return e.Path("/var/log/apache2")
}
