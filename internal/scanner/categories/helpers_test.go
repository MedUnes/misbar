package categories_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/medunes/misbar/internal/scanner"
)

// fixedNow is the pinned clock for tests, so "recently modified" checks are
// deterministic against explicitly-stamped file mtimes.
var fixedNow = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

// writeTree builds a fixture rootfs under a temp dir from rel-path→content and
// returns the root. It is the root-injection seam: env.Path prefixes this root.
func writeTree(t *testing.T, files map[string]string) string {
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
	return root
}

// testEnv returns an Env rooted at root with the clock pinned to fixedNow and
// the distro forced to Debian (so tests never depend on the host).
func testEnv(root string) *scanner.Env {
	return scanner.NewEnv(root, time.Hour,
		scanner.WithClock(func() time.Time { return fixedNow }),
		scanner.WithDistro(scanner.FamilyDebian))
}

// testEnvRun is testEnv plus a stubbed command runner (for ss/dmesg/which…).
func testEnvRun(root string, run scanner.CmdRunner) *scanner.Env {
	return scanner.NewEnv(root, time.Hour,
		scanner.WithClock(func() time.Time { return fixedNow }),
		scanner.WithDistro(scanner.FamilyDebian),
		scanner.WithRunner(run))
}

// chtime stamps a file's mtime, relative to the pinned clock.
func chtime(t *testing.T, path string, mod time.Time) {
	t.Helper()
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

// runArtifact finds an artifact by ID in a category and runs its scan.
func runArtifact(t *testing.T, sc scanner.Scanner, env *scanner.Env, id scanner.ArtifactID) scanner.ScanResult {
	t.Helper()
	for _, a := range sc.Artifacts(env) {
		if a.ID == id {
			return a.Scan(context.Background(), env)
		}
	}
	t.Fatalf("artifact %q not found in category %s", id, sc.Meta().Label)
	return scanner.ScanResult{}
}

// buildUtmp assembles one 384-byte utmp record for wtmp/btmp fixtures.
func buildUtmp(typ int16, user, line, host string, ts time.Time) []byte {
	b := make([]byte, 384)
	binary.LittleEndian.PutUint16(b[0:], uint16(typ))
	copy(b[8:40], line)
	copy(b[44:76], user)
	copy(b[76:332], host)
	binary.LittleEndian.PutUint32(b[340:], uint32(ts.Unix()))
	return b
}

// hasAnomaly reports whether any anomaly title contains substr.
func hasAnomaly(r scanner.ScanResult, substr string) bool {
	for _, a := range r.Anomalies {
		if strings.Contains(a.Title, substr) {
			return true
		}
	}
	return false
}
