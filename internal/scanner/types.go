// Package scanner defines misbar's read-only artifact model: the Health/Result
// types, the root-injectable Env seam (paths, allowlisted commands, clock), the
// anomaly engine, and the bounded worker-pool orchestrator that streams results.
// Concrete per-category scanners live in the categories subpackage.
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

// CategoryID identifies one of the seven artifact categories. Values match the
// spec's dashboard numbering (1–6 main panels, 7 the toolbox footer).
type CategoryID uint8

const (
	CatSystemLogs  CategoryID = iota + 1 // 1
	CatNetwork                           // 2
	CatAuthUsers                         // 3
	CatFilesystem                        // 4
	CatPersistence                       // 5
	CatServices                          // 6
	CatToolbox                           // 7
)

// ArtifactID is a stable identifier for an artifact (e.g. "ld.so.preload"),
// used to key results and reference anomalies.
type ArtifactID string

// Mode is how an artifact is observed: scanned once (static) or tailed (live).
type Mode uint8

const (
	ModeStatic Mode = iota
	ModeLive
)

// DistroFamily is a package/log-layout family. Zero means "unknown".
type DistroFamily uint8

const (
	FamilyDebian DistroFamily = 1 << iota // apt, /var/log/syslog, auth.log
	FamilyRHEL                            // dnf/yum, /var/log/messages, secure
)

func (f DistroFamily) String() string {
	switch f {
	case FamilyDebian:
		return "debian"
	case FamilyRHEL:
		return "rhel"
	default:
		return "unknown"
	}
}

// DistroSet restricts an artifact to certain families. The zero value matches
// every family (artifact is distro-agnostic).
type DistroSet uint8

// Matches reports whether an artifact restricted to this set applies to family.
func (s DistroSet) Matches(family DistroFamily) bool {
	return s == 0 || s&DistroSet(family) != 0
}

// LiveSource describes how a live artifact streams: a file to tail, or a
// command re-run every Interval. Wired up in M3.
type LiveSource struct {
	Path     string
	Cmd      []string
	Interval time.Duration
}

// Artifact is a single checkable thing. Scan produces its static result; Live
// (when Mode==ModeLive) tells the tailer how to stream updates.
type Artifact struct {
	ID        ArtifactID
	Category  CategoryID
	Label     string
	Mode      Mode
	NeedsRoot bool
	Distros   DistroSet // 0 == all families
	Scan      func(ctx context.Context, env *Env) ScanResult
	Live      *LiveSource
}

// CategoryMeta is the dashboard identity of a category.
type CategoryMeta struct {
	ID    CategoryID
	Label string
}

// AllCategoryMeta returns the six main dashboard categories in grid order. The
// TUI renders one panel per entry; a category without a registered scanner yet
// simply shows no data.
func AllCategoryMeta() []CategoryMeta {
	return []CategoryMeta{
		{CatSystemLogs, "System Logs"},
		{CatNetwork, "Network"},
		{CatAuthUsers, "Auth & Users"},
		{CatFilesystem, "Filesystem"},
		{CatPersistence, "Persistence"},
		{CatServices, "Services & Cron"},
	}
}

// Scanner is one self-contained category. Implementations live in
// internal/scanner/categories and never import each other.
type Scanner interface {
	Meta() CategoryMeta
	Artifacts(env *Env) []Artifact
}

// CmdRunner executes an allowlisted command and returns its stdout. Tests inject
// a stub keyed on argv; production uses execRunner.
type CmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// allowedCommands is the complete, closed set of programs misbar may execute.
// Anything outside it is refused before exec — no shell, no interpolation.
var allowedCommands = map[string]bool{
	"ss": true, "dmesg": true, "last": true, "lastb": true,
	"journalctl": true, "which": true, "uname": true, "id": true,
}

// Env is the root-injectable testability seam. Every path a scanner touches
// goes through Path; every command through Cmd; every "recent?" check through
// Now and Since.
type Env struct {
	root   string
	run    CmdRunner
	now    func() time.Time
	Since  time.Duration
	Distro DistroFamily
}

// EnvOption configures an Env at construction.
type EnvOption func(*Env)

// WithRunner overrides the command runner (tests inject a stub).
func WithRunner(r CmdRunner) EnvOption { return func(e *Env) { e.run = r } }

// WithClock overrides the clock used for recency checks (tests pin it).
func WithClock(now func() time.Time) EnvOption { return func(e *Env) { e.now = now } }

// WithDistro forces a distro family instead of detecting it.
func WithDistro(f DistroFamily) EnvOption { return func(e *Env) { e.Distro = f } }

// NewEnv builds an Env rooted at root (use "" or "/" for the live system) with
// the given anomaly window. Distro is auto-detected unless WithDistro is given.
func NewEnv(root string, since time.Duration, opts ...EnvOption) *Env {
	e := &Env{
		root:  root,
		run:   execRunner,
		now:   time.Now,
		Since: since,
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.Distro == 0 {
		e.Distro = DetectDistro(e)
	}
	return e
}

// Path composes the configured root with an absolute target path so scanners
// never hardcode /etc and tests can point at a fixture rootfs.
func (e *Env) Path(p string) string {
	if e.root == "" {
		return p
	}
	return filepath.Join(e.root, p)
}

// Now returns the current time from the injected clock.
func (e *Env) Now() time.Time { return e.now() }

// Cmd runs an allowlisted command with no shell. A command outside the allowlist
// is refused. The caller's ctx carries the per-job timeout.
func (e *Env) Cmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !allowedCommands[name] {
		return nil, fmt.Errorf("command %q is not allowed", name)
	}
	return e.run(ctx, name, args...)
}

// HasCommand reports whether name resolves on PATH, checked via the allowlisted
// `which`. Used by the toolbox to probe forensic-tool availability; the probed
// tool itself is never executed.
func (e *Env) HasCommand(ctx context.Context, name string) bool {
	out, err := e.Cmd(ctx, "which", name)
	return err == nil && len(bytes.TrimSpace(out)) > 0
}

// execRunner is the production CmdRunner: a shell-less os/exec call.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, path, args...).Output()
}
