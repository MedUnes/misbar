package report_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/medunes/misbar/internal/report"
	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/scanner/categories"
)

func fixtureOrch(t *testing.T, files map[string]string) *scanner.Orchestrator {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env := scanner.NewEnv(root, time.Hour, scanner.WithDistro(scanner.FamilyDebian))
	return scanner.NewOrchestrator(env, categories.All()...)
}

func TestCollectJSONAndText(t *testing.T) {
	orch := fixtureOrch(t, map[string]string{
		"etc/ld.so.preload": "/tmp/evil.so\n", // instant CRIT
	})
	rep := report.Collect(context.Background(), orch)

	// JSON is valid and structurally complete.
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(rep.Categories) != 6 {
		t.Errorf("categories = %d, want 6", len(rep.Categories))
	}
	if rep.Counts.Crit < 1 {
		t.Errorf("crit count = %d, want ≥1 (ld.so.preload)", rep.Counts.Crit)
	}

	// The text report surfaces the critical finding.
	var text bytes.Buffer
	if err := report.WriteText(&text, rep, false); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := text.String()
	if !strings.Contains(out, "Persistence") || !strings.Contains(out, "ld.so.preload") {
		t.Errorf("report missing the ld.so.preload finding:\n%s", out)
	}
}

func TestCollectSurfacesMultipleAnomalies(t *testing.T) {
	// Plant three independent red flags across categories; all must appear.
	orch := fixtureOrch(t, map[string]string{
		"etc/ld.so.preload": "/tmp/evil.so\n",                    // Persistence CRIT
		"etc/sudoers":       "alice ALL=(ALL) NOPASSWD: ALL\n",   // Auth WARN
		"etc/passwd":        "backdoor:x:0:0::/root:/bin/bash\n", // Auth CRIT (UID 0)
	})
	rep := report.Collect(context.Background(), orch)

	var text bytes.Buffer
	if err := report.WriteText(&text, rep, false); err != nil {
		t.Fatal(err)
	}
	out := text.String()
	for _, want := range []string{"ld.so.preload", "NOPASSWD", "UID 0"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestCollectEmptyRootDegradesGracefully(t *testing.T) {
	// A bare root: every artifact is missing. The scan must complete with no
	// panic and produce a well-formed, all-SKIP report.
	orch := fixtureOrch(t, map[string]string{"etc/hostname": "box\n"})
	rep := report.Collect(context.Background(), orch)

	if len(rep.Categories) != 6 {
		t.Fatalf("categories = %d, want 6", len(rep.Categories))
	}
	if rep.Counts.Crit != 0 {
		t.Errorf("empty root produced %d crit, want 0", rep.Counts.Crit)
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON on empty root: %v", err)
	}
}
