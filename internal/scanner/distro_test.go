package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeOSRelease(t *testing.T, content string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestDetectRHELPaths(t *testing.T) {
	root := writeOSRelease(t, "ID=\"rhel\"\nID_LIKE=\"fedora\"\n")
	env := NewEnv(root, time.Hour) // auto-detect

	if env.Distro != FamilyRHEL {
		t.Fatalf("distro = %v, want RHEL", env.Distro)
	}
	checks := map[string]string{
		env.SyslogPath():  filepath.Join(root, "var/log/messages"),
		env.AuthLogPath(): filepath.Join(root, "var/log/secure"),
		env.PkgLogPath():  filepath.Join(root, "var/log/yum.log"),
		env.WebLogDir():   filepath.Join(root, "var/log/httpd"),
	}
	for got, want := range checks {
		if got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}
}

func TestDetectDebianPaths(t *testing.T) {
	root := writeOSRelease(t, "ID=ubuntu\nID_LIKE=debian\n")
	env := NewEnv(root, time.Hour)

	if env.Distro != FamilyDebian {
		t.Fatalf("distro = %v, want Debian", env.Distro)
	}
	if env.AuthLogPath() != filepath.Join(root, "var/log/auth.log") {
		t.Errorf("auth log = %q, want auth.log", env.AuthLogPath())
	}
	if env.WebLogDir() != filepath.Join(root, "var/log/apache2") {
		t.Errorf("web log = %q, want apache2", env.WebLogDir())
	}
}

func TestDetectFallbackToDebian(t *testing.T) {
	// No os-release and no distinctive files → default Debian.
	env := NewEnv(t.TempDir(), time.Hour)
	if env.Distro != FamilyDebian {
		t.Errorf("empty root distro = %v, want Debian default", env.Distro)
	}
}
