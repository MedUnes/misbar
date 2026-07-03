package categories_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/scanner/categories"
)

func TestHostsHijackIsCrit(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/hosts": "127.0.0.1 localhost\n1.2.3.4 google.com www.google.com\n",
	})
	res := runArtifact(t, categories.Network(), testEnv(root), "hosts")
	if res.Health != scanner.HealthCrit {
		t.Fatalf("health = %v, want CRIT", res.Health)
	}
	if !hasAnomaly(res, "hijack") {
		t.Errorf("expected a hijack anomaly, got %+v", res.Anomalies)
	}
}

func TestHostsCleanIsOK(t *testing.T) {
	root := writeTree(t, map[string]string{"etc/hosts": "127.0.0.1 localhost\n127.0.1.1 myhost\n"})
	res := runArtifact(t, categories.Network(), testEnv(root), "hosts")
	if res.Health != scanner.HealthOK {
		t.Errorf("clean hosts health = %v, want OK", res.Health)
	}
}

func TestResolvNameservers(t *testing.T) {
	root := writeTree(t, map[string]string{"etc/resolv.conf": "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"})
	res := runArtifact(t, categories.Network(), testEnv(root), "resolv.conf")
	if !strings.Contains(res.Summary, "2 nameservers") {
		t.Errorf("summary = %q, want 2 nameservers", res.Summary)
	}
}

func TestListeningPortsViaStub(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ss" {
			return []byte("Netid State Local Peer Process\n" +
				"tcp LISTEN 0.0.0.0:22 users:((\"sshd\"))\n" +
				"tcp LISTEN 0.0.0.0:80 users:((\"nginx\"))\n"), nil
		}
		return nil, fmt.Errorf("unexpected command %q", name)
	}
	res := runArtifact(t, categories.Network(), testEnvRun(t.TempDir(), run), "listening-ports")
	if res.Health != scanner.HealthOK {
		t.Errorf("health = %v, want OK", res.Health)
	}
	if !strings.Contains(res.Summary, "2 listening") {
		t.Errorf("summary = %q, want 2 listening ports", res.Summary)
	}
}
