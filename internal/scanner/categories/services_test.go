package categories_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/scanner/categories"
)

func TestCronDeniedDirIsReportedLocked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	root := writeTree(t, map[string]string{
		"var/spool/cron/crontabs/root": "* * * * * /opt/evil\n",
	})
	dir := filepath.Join(root, "var/spool/cron/crontabs")
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) }) // let t.TempDir clean up

	res := runArtifact(t, categories.Services(), testEnv(root), "cron")
	if !res.Locked {
		t.Errorf("permission-denied cron dir should set Locked; got %+v", res)
	}
}

func TestCronRecentlyModifiedIsWarn(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/crontab":       "17 * * * * root cd / && run-parts /etc/cron.hourly\n",
		"etc/cron.d/backup": "0 2 * * * root /usr/local/bin/backup.sh\n",
	})
	chtime(t, filepath.Join(root, "etc/crontab"), fixedNow.AddDate(0, 0, -60))
	chtime(t, filepath.Join(root, "etc/cron.d/backup"), fixedNow.AddDate(0, 0, -1))

	res := runArtifact(t, categories.Services(), testEnv(root), "cron")
	if res.Health != scanner.HealthWarn {
		t.Fatalf("health = %v, want WARN", res.Health)
	}
	if !hasAnomaly(res, "cron") {
		t.Errorf("expected a cron anomaly, got %+v", res.Anomalies)
	}
}

func TestBrowserProfileOnServerIsWarn(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/passwd": "alice:x:1000:1000::/home/alice:/bin/bash\n",
		"home/alice/.mozilla/firefox/abcd.default/prefs.js": "user_pref();\n",
	})
	res := runArtifact(t, categories.Services(), testEnv(root), "browsers")
	if res.Health != scanner.HealthWarn {
		t.Fatalf("health = %v, want WARN", res.Health)
	}
	if !hasAnomaly(res, "browser") {
		t.Errorf("expected a browser anomaly, got %+v", res.Anomalies)
	}
}

func TestMailSpool(t *testing.T) {
	root := writeTree(t, map[string]string{
		"var/mail/alice": "From root  Wed\nSubject: hi\n",
		"var/mail/empty": "",
	})
	res := runArtifact(t, categories.Services(), testEnv(root), "mail")
	if res.Health != scanner.HealthOK {
		t.Errorf("health = %v, want OK", res.Health)
	}
	// Only the non-empty spool counts.
	if res.Summary != "1 user with mail" {
		t.Errorf("summary = %q, want 1 user with mail", res.Summary)
	}
}
