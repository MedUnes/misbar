package categories

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/medunes/misbar/internal/fsutil"
	"github.com/medunes/misbar/internal/scanner"
)

// filesystem implements the category-4 scanner: suspicious files in world-
// writable dirs, mount drift, and recent changes to sensitive directories.
type filesystem struct{}

// Filesystem returns the category-4 scanner.
func Filesystem() scanner.Scanner { return filesystem{} }

func (filesystem) Meta() scanner.CategoryMeta {
	return scanner.CategoryMeta{ID: scanner.CatFilesystem, Label: "Filesystem"}
}

func (filesystem) Artifacts(*scanner.Env) []scanner.Artifact {
	cat := scanner.CatFilesystem
	return []scanner.Artifact{
		{ID: "tmp", Category: cat, Label: "/tmp", Scan: scanExecDir("tmp", "/tmp", scanner.HealthWarn)},
		{ID: "var-tmp", Category: cat, Label: "/var/tmp", Scan: scanExecDir("var-tmp", "/var/tmp", scanner.HealthWarn)},
		{ID: "dev-shm", Category: cat, Label: "/dev/shm", Scan: scanExecDir("dev-shm", "/dev/shm", scanner.HealthCrit)},
		{ID: "mounts", Category: cat, Label: "/proc/mounts", Scan: scanMounts},
		{ID: "fstab", Category: cat, Label: "/etc/fstab", Scan: simpleFile("fstab", cat, "/etc/fstab")},
		{ID: "mtab", Category: cat, Label: "/etc/mtab", Scan: simpleFile("mtab", cat, "/etc/mtab")},
		{ID: "lvm-backup", Category: cat, Label: "/etc/lvm/backup/", Scan: scanDirRecent("lvm-backup", cat, "/etc/lvm/backup", scanner.RecentWindow7d, "LVM backup")},
		{ID: "etc-recent", Category: cat, Label: "/etc (recent)", Scan: scanRecentDir("etc-recent", "/etc")},
		{ID: "usr-bin-recent", Category: cat, Label: "/usr/bin (recent)", Scan: scanRecentDir("usr-bin-recent", "/usr/bin")},
	}
}

// largeFileThreshold is the size above which a file in a temp dir is "unusually
// large" and worth a look (staged exfil, memory dumps, …).
const largeFileThreshold = 100 << 20 // 100 MiB

// scanExecDir flags executable, hidden, and unusually-large files in a world-
// writable directory (per misbar-spec.md). Executables in /tmp, /var/tmp,
// /dev/shm are classic malware staging. Only regular files count as executable
// so a benign symlink (lstat reports 0777) is not a false positive.
func scanExecDir(id scanner.ArtifactID, path string, execSeverity scanner.Health) scanFunc {
	return func(_ context.Context, env *scanner.Env) scanner.ScanResult {
		entries, err := fsutil.ListDir(env.Path(path))
		health, locked := scanner.Classify(err)
		res := scanner.ScanResult{Category: scanner.CatFilesystem, Artifact: id, Health: health, Locked: locked, Err: err}
		if err != nil {
			res.Summary = presenceSummary(health, locked)
			return res
		}

		var names, execs, hidden, large []string
		for _, e := range entries {
			names = append(names, e.Name())
			if e.IsDir() {
				continue
			}
			if strings.HasPrefix(e.Name(), ".") {
				hidden = append(hidden, e.Name())
			}
			info, ierr := e.Info()
			if ierr != nil || !info.Mode().IsRegular() {
				continue // skip symlinks, sockets, devices, fifos
			}
			if info.Mode().Perm()&0o111 != 0 {
				execs = append(execs, e.Name())
			}
			if info.Size() > largeFileThreshold {
				large = append(large, fmt.Sprintf("%s (%d MiB)", e.Name(), info.Size()>>20))
			}
		}
		slices.Sort(names)
		res.Content = scanner.Content{Text: strings.Join(names, "\n")}
		res.Health = scanner.HealthOK
		res.Summary = fmt.Sprintf("%d entr%s", len(names), plural(len(names), "y", "ies"))

		add := func(sev scanner.Health, title, detail string, evidence []string) {
			if len(evidence) == 0 {
				return
			}
			slices.Sort(evidence)
			res.Health = max(res.Health, sev)
			res.Anomalies = append(res.Anomalies, scanner.Anomaly{
				Severity: sev, Title: title, Detail: detail, Evidence: evidence, Artifact: id,
			})
		}
		add(execSeverity, "executable file in "+path, "Executables here are a common malware staging pattern.", execs)
		add(scanner.HealthWarn, "hidden file in "+path, "Dotfiles in a world-writable directory can conceal payloads.", hidden)
		add(scanner.HealthWarn, "unusually large file in "+path, "Large temp files can be staged exfiltration or memory dumps.", large)

		if len(res.Anomalies) > 0 {
			parts := []string{fmt.Sprintf("%d entries", len(names))}
			for _, p := range []struct {
				n int
				s string
			}{{len(execs), "exec"}, {len(hidden), "hidden"}, {len(large), "large"}} {
				if p.n > 0 {
					parts = append(parts, fmt.Sprintf("%d %s", p.n, p.s))
				}
			}
			res.Summary = strings.Join(parts, ", ")
		}
		return res
	}
}

// unusualMountTypes are filesystem types worth flagging when mounted.
var unusualMountTypes = []string{"fuse", "fuse.sshfs", "nfs", "nfs4", "cifs", "smbfs"}

// scanMounts flags unusual mount types in /proc/mounts.
func scanMounts(_ context.Context, env *scanner.Env) scanner.ScanResult {
	res := fileResult("mounts", scanner.CatFilesystem, env.Path("/proc/mounts"))
	if res.Err != nil {
		setAbsent(&res)
		return res
	}
	var unusual []string
	for _, line := range scanner.NonEmptyLines(res.Content.Text) {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if slices.Contains(unusualMountTypes, fields[2]) {
			unusual = append(unusual, fields[0]+" on "+fields[1]+" ("+fields[2]+")")
		}
	}
	res.Health = scanner.HealthOK
	res.Summary = "no unusual mounts"
	if len(unusual) > 0 {
		res.Health = scanner.HealthWarn
		res.Summary = fmt.Sprintf("%d unusual mount%s", len(unusual), plural(len(unusual), "", "s"))
		res.Anomalies = append(res.Anomalies, scanner.Anomaly{
			Severity: scanner.HealthWarn,
			Title:    "unusual mount type",
			Detail:   "Network or FUSE mounts can exfiltrate data or hide files.",
			Evidence: unusual,
			Artifact: "mounts",
		})
	}
	return res
}

// scanRecentDir flags files in a sensitive directory modified within 24h. The
// listing is shallow (non-recursive) to stay bounded.
func scanRecentDir(id scanner.ArtifactID, path string) scanFunc {
	return func(_ context.Context, env *scanner.Env) scanner.ScanResult {
		entries, err := fsutil.ListDir(env.Path(path))
		health, locked := scanner.Classify(err)
		res := scanner.ScanResult{Category: scanner.CatFilesystem, Artifact: id, Health: health, Locked: locked, Err: err}
		if err != nil {
			res.Summary = presenceSummary(health, locked)
			return res
		}

		now := env.Now()
		var recent []string
		for _, e := range entries {
			if info, ierr := e.Info(); ierr == nil && scanner.RecentlyModified(info, scanner.RecentWindow, now) {
				recent = append(recent, e.Name())
			}
		}
		res.Health = scanner.HealthOK
		res.Summary = "no recent changes"
		if len(recent) > 0 {
			slices.Sort(recent)
			res.Content = scanner.Content{Text: strings.Join(recent, "\n")}
			res.Health = scanner.HealthWarn
			res.Summary = fmt.Sprintf("%d changed in 24h", len(recent))
			res.Anomalies = append(res.Anomalies, scanner.Anomaly{
				Severity: scanner.HealthWarn,
				Title:    "recently modified files in " + path,
				Detail:   "Recent changes to system directories warrant a look.",
				Evidence: recent,
				Artifact: id,
			})
		}
		return res
	}
}
