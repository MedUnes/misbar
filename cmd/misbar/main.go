// Command misbar is a read-only Linux forensic-artifact TUI
// for SRE incident triage. It observes only: no writes, no network, no CGO.
// See misbar-spec.md for the full artifact taxonomy.
//
// Running with no flags launches the interactive dashboard. Headless
// (--json/--report) modes arrive in later milestones.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/medunes/misbar/internal/report"
	"github.com/medunes/misbar/internal/scanner"
	"github.com/medunes/misbar/internal/scanner/categories"
	"github.com/medunes/misbar/internal/tui"
)

// version is overridden at build time via -ldflags "-X main.version=...".
// When unset (e.g. `go run`), buildVersion falls back to VCS build info.
var version = ""

const usage = `misbar — read-only Linux forensic-artifact TUI

Usage:
  misbar [flags]

Run with no flags to launch the interactive dashboard.

Flags:
  --category <N>      Launch directly into category N (1-6)
  --no-live           Disable live tailing (static scan only)
  --json              Dump scan results as JSON to stdout and exit
  --report            Dump a human-readable report to stdout and exit
  --since <duration>  Time window for anomaly detection (default: 1h)
  --verbose           Include OK artifacts in the report; log to stderr
  --version           Show version and exit
  --help              Show this help and exit
`

// config holds the resolved CLI options. It grows as later milestones add flags
// (--since, --no-live, --json, …).
type config struct {
	since    time.Duration
	category int  // 1..6 to deep-link into a category, 0 for the overview
	noLive   bool // disable live tailing / periodic refresh
	json     bool // dump JSON and exit
	report   bool // dump text report and exit
	verbose  bool // include OK artifacts; log to stderr
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, launchApp))
}

// run is the testable entry point: args, output streams, and the launcher are
// injected so behavior can be asserted without touching global state or starting
// a real terminal program.
func run(args []string, stdout, stderr io.Writer, launch func(config) error) int {
	fs := flag.NewFlagSet("misbar", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }

	showVersion := fs.Bool("version", false, "show version and exit")
	category := fs.Int("category", 0, "launch directly into category N (1-6)")
	noLive := fs.Bool("no-live", false, "disable live tailing (static scan only)")
	asJSON := fs.Bool("json", false, "dump scan results as JSON and exit")
	asReport := fs.Bool("report", false, "dump a human-readable report and exit")
	since := fs.Duration("since", time.Hour, "time window for anomaly detection")
	verbose := fs.Bool("verbose", false, "include OK artifacts; log to stderr")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // --help / -h: usage already printed by the flag package.
		}
		return 2 // parse error: message + usage already printed to stderr.
	}

	if *showVersion {
		fmt.Fprintln(stdout, "misbar", buildVersion())
		return 0
	}

	if *category < 0 || *category > 6 {
		fmt.Fprintln(stderr, "misbar: --category must be between 1 and 6")
		return 2
	}

	cfg := config{
		since:    *since,
		category: *category,
		noLive:   *noLive,
		json:     *asJSON,
		report:   *asReport,
		verbose:  *verbose,
	}
	if err := launch(cfg); err != nil {
		fmt.Fprintln(stderr, "misbar:", err)
		return 1
	}
	return 0
}

// launchApp builds the scan orchestrator for the live system, then either dumps
// a headless report (--json/--report) or runs the interactive TUI under a
// context cancelled on SIGINT/SIGTERM for clean shutdown.
func launchApp(cfg config) error {
	env := scanner.NewEnv("", cfg.since)
	orch := scanner.NewOrchestrator(env, categories.All()...)

	if cfg.json || cfg.report {
		if cfg.verbose {
			fmt.Fprintln(os.Stderr, "misbar: scanning", env.Distro, "host…")
		}
		rep := report.Collect(context.Background(), orch)
		rep.Generated = time.Now().UTC().Format(time.RFC3339)
		if cfg.json {
			return report.WriteJSON(os.Stdout, rep)
		}
		return report.WriteText(os.Stdout, rep, cfg.verbose)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return tui.Run(ctx, orch, tui.Options{StartCategory: cfg.category, NoLive: cfg.noLive})
}

// buildVersion resolves the binary's version: the ldflags-injected value if
// present, otherwise the module version or short VCS revision from build info.
func buildVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, suffix string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				suffix = "-dirty"
			}
		}
	}
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		return rev + suffix
	}
	return "dev"
}
