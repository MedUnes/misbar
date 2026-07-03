package categories_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/scanner/categories"
)

func TestLdSoPreloadNonEmptyIsCrit(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/ld.so.preload": "/usr/lib/libncurses.so.5\n/tmp/evil.so\n",
	})
	res := runArtifact(t, categories.Persistence(), testEnv(root), "ld.so.preload")

	if res.Health != scanner.HealthCrit {
		t.Fatalf("health = %v, want CRIT", res.Health)
	}
	if !hasAnomaly(res, "ld.so.preload") {
		t.Errorf("expected an ld.so.preload anomaly, got %+v", res.Anomalies)
	}
	if len(res.Anomalies) == 0 || len(res.Anomalies[0].Evidence) != 2 {
		t.Errorf("expected 2 evidence lines, got %+v", res.Anomalies)
	}
}

func TestLdSoPreloadEmptyIsOK(t *testing.T) {
	root := writeTree(t, map[string]string{"etc/ld.so.preload": "\n  \n"})
	res := runArtifact(t, categories.Persistence(), testEnv(root), "ld.so.preload")
	if res.Health != scanner.HealthOK {
		t.Errorf("empty preload health = %v, want OK", res.Health)
	}
}

func TestLdSoPreloadAbsentIsSkip(t *testing.T) {
	root := writeTree(t, map[string]string{"etc/hostname": "box\n"})
	res := runArtifact(t, categories.Persistence(), testEnv(root), "ld.so.preload")
	if res.Health != scanner.HealthSkip {
		t.Errorf("absent preload health = %v, want SKIP", res.Health)
	}
}

func TestSSHDPermitRootLoginIsCrit(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/ssh/sshd_config": "# comment\nPort 22\nPermitRootLogin yes\nPasswordAuthentication yes\n",
	})
	res := runArtifact(t, categories.Persistence(), testEnv(root), "sshd_config")
	if res.Health != scanner.HealthCrit {
		t.Errorf("health = %v, want CRIT", res.Health)
	}
	if !hasAnomaly(res, "PermitRootLogin") {
		t.Errorf("expected PermitRootLogin anomaly, got %+v", res.Anomalies)
	}
}

func TestSSHDCommentedDirectiveIgnored(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/ssh/sshd_config": "#PermitRootLogin yes\nPermitRootLogin no\n",
	})
	res := runArtifact(t, categories.Persistence(), testEnv(root), "sshd_config")
	if res.Health != scanner.HealthOK {
		t.Errorf("commented directive health = %v, want OK", res.Health)
	}
}

func TestRCLocalNonDefaultIsWarn(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/rc.local": "#!/bin/sh\n/opt/backdoor &\nexit 0\n",
	})
	res := runArtifact(t, categories.Persistence(), testEnv(root), "rc.local")
	if res.Health != scanner.HealthWarn {
		t.Errorf("health = %v, want WARN", res.Health)
	}
}

func TestRCLocalDefaultIsOK(t *testing.T) {
	root := writeTree(t, map[string]string{"etc/rc.local": "#!/bin/sh\n# nothing here\nexit 0\n"})
	res := runArtifact(t, categories.Persistence(), testEnv(root), "rc.local")
	if res.Health != scanner.HealthOK {
		t.Errorf("health = %v, want OK", res.Health)
	}
}

func TestInitDRecentlyModifiedIsWarn(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/init.d/ssh":    "#!/bin/sh\n",
		"etc/init.d/sneaky": "#!/bin/sh\n# added by attacker\n",
	})
	// ssh is old, sneaky is fresh (within the 7-day window).
	chtime(t, filepath.Join(root, "etc/init.d/ssh"), fixedNow.AddDate(0, 0, -30))
	chtime(t, filepath.Join(root, "etc/init.d/sneaky"), fixedNow.AddDate(0, 0, -1))

	res := runArtifact(t, categories.Persistence(), testEnv(root), "init.d")
	if res.Health != scanner.HealthWarn {
		t.Fatalf("health = %v, want WARN", res.Health)
	}
	if !hasAnomaly(res, "recently modified") {
		t.Errorf("expected recency anomaly, got %+v", res.Anomalies)
	}
	// The listing content should include both scripts.
	if !strings.Contains(res.Content.Text, "sneaky") {
		t.Errorf("content missing sneaky: %q", res.Content.Text)
	}
}
