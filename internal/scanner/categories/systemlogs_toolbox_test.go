package categories_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/scanner/categories"
)

func TestSyslogSeverityCounting(t *testing.T) {
	root := writeTree(t, map[string]string{
		"var/log/syslog": "Jan 1 host app: started ok\n" +
			"Jan 1 host app: ERROR failed to bind\n" +
			"Jan 1 host app: WARNING retrying\n",
	})
	res := runArtifact(t, categories.SystemLogs(), testEnv(root), "syslog")
	if res.Health != scanner.HealthWarn {
		t.Fatalf("health = %v, want WARN", res.Health)
	}
	if !strings.Contains(res.Summary, "err") || !strings.Contains(res.Summary, "warn") {
		t.Errorf("summary = %q, want error and warning counts", res.Summary)
	}
}

func TestSyslogKernelPanicIsCrit(t *testing.T) {
	root := writeTree(t, map[string]string{
		"var/log/kern.log": "kernel: Kernel panic - not syncing: Fatal exception\n",
	})
	res := runArtifact(t, categories.SystemLogs(), testEnv(root), "kern.log")
	if res.Health != scanner.HealthCrit {
		t.Errorf("health = %v, want CRIT", res.Health)
	}
}

func TestDmesgViaStub(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "dmesg" {
			return []byte("[  1.0] usb error\n[  2.0] acpi warning\n"), nil
		}
		return nil, fmt.Errorf("unexpected %q", name)
	}
	res := runArtifact(t, categories.SystemLogs(), testEnvRun(t.TempDir(), run), "dmesg")
	if !strings.Contains(res.Summary, "2 err/warn") {
		t.Errorf("summary = %q, want 2 err/warn lines", res.Summary)
	}
}

func TestToolboxAvailability(t *testing.T) {
	present := map[string]bool{"dd": true, "sha256sum": true, "fls": true}
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "which" && len(args) == 1 && present[args[0]] {
			return []byte("/usr/bin/" + args[0] + "\n"), nil
		}
		return nil, fmt.Errorf("not found")
	}
	res := runArtifact(t, categories.Toolbox(), testEnvRun(t.TempDir(), run), "tools")

	got := make(map[string]scanner.Health, len(res.Findings))
	for _, f := range res.Findings {
		got[f.Message] = f.Severity
	}
	if got["dd"] != scanner.HealthOK {
		t.Error("dd should be available")
	}
	if got["sleuthkit"] != scanner.HealthOK {
		t.Error("sleuthkit should be available (fls present)")
	}
	if got["volatility"] != scanner.HealthSkip {
		t.Error("volatility should be missing")
	}
}
