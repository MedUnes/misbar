package categories_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/scanner/categories"
)

func TestExecDirSymlinkNotFlagged(t *testing.T) {
	root := writeTree(t, map[string]string{"dev/shm/real": "data"})
	// A symlink lstat's as 0777 (all exec bits); it must NOT be flagged.
	if err := os.Symlink("real", filepath.Join(root, "dev/shm/link")); err != nil {
		t.Fatal(err)
	}
	res := runArtifact(t, categories.Filesystem(), testEnv(root), "dev-shm")
	if hasAnomaly(res, "executable") {
		t.Errorf("symlink flagged as executable (false positive); anomalies=%+v", res.Anomalies)
	}
	if res.Health == scanner.HealthCrit {
		t.Errorf("health = %v, want not CRIT for a benign symlink", res.Health)
	}
}

func TestTmpHiddenFileIsWarn(t *testing.T) {
	root := writeTree(t, map[string]string{"tmp/.stager": "payload"})
	res := runArtifact(t, categories.Filesystem(), testEnv(root), "tmp")
	if res.Health != scanner.HealthWarn {
		t.Fatalf("health = %v, want WARN for a hidden file", res.Health)
	}
	if !hasAnomaly(res, "hidden file") {
		t.Errorf("expected a hidden-file anomaly, got %+v", res.Anomalies)
	}
}

func TestDevShmExecutableIsCrit(t *testing.T) {
	root := writeTree(t, map[string]string{"dev/shm/payload": "ELF..."})
	if err := os.Chmod(filepath.Join(root, "dev/shm/payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := runArtifact(t, categories.Filesystem(), testEnv(root), "dev-shm")
	if res.Health != scanner.HealthCrit {
		t.Fatalf("health = %v, want CRIT", res.Health)
	}
	if !hasAnomaly(res, "executable") {
		t.Errorf("expected an executable anomaly, got %+v", res.Anomalies)
	}
}

func TestTmpExecutableIsWarn(t *testing.T) {
	root := writeTree(t, map[string]string{"tmp/build.sh": "#!/bin/sh"})
	if err := os.Chmod(filepath.Join(root, "tmp/build.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := runArtifact(t, categories.Filesystem(), testEnv(root), "tmp")
	if res.Health != scanner.HealthWarn {
		t.Errorf("health = %v, want WARN", res.Health)
	}
}

func TestTmpNonExecutableIsOK(t *testing.T) {
	root := writeTree(t, map[string]string{"tmp/notes.txt": "just notes"})
	if err := os.Chmod(filepath.Join(root, "tmp/notes.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runArtifact(t, categories.Filesystem(), testEnv(root), "tmp")
	if res.Health != scanner.HealthOK {
		t.Errorf("health = %v, want OK", res.Health)
	}
}

func TestMountsUnusualIsWarn(t *testing.T) {
	root := writeTree(t, map[string]string{
		"proc/mounts": "proc /proc proc rw 0 0\nremote:/share /mnt/x nfs rw 0 0\n",
	})
	res := runArtifact(t, categories.Filesystem(), testEnv(root), "mounts")
	if res.Health != scanner.HealthWarn {
		t.Fatalf("health = %v, want WARN", res.Health)
	}
	if !hasAnomaly(res, "unusual mount") {
		t.Errorf("expected an unusual-mount anomaly, got %+v", res.Anomalies)
	}
}
