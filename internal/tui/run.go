package tui

import (
	"context"
	"errors"

	tea "charm.land/bubbletea/v2"

	"github.com/medunes/misbar/internal/scanner"
)

// Options configures a TUI run.
type Options struct {
	StartCategory int  // 1..6 to deep-link into a category, 0 for the overview
	NoLive        bool // disable live tailing and periodic refresh
}

// Run starts the interactive dashboard over the given orchestrator and blocks
// until the user quits or ctx is cancelled (e.g. SIGTERM). Cancelling ctx tears
// down the scan and every live tailer cleanly.
func Run(ctx context.Context, orch *scanner.Orchestrator, opts Options) error {
	app := New(orch)
	app.parentCtx = ctx
	app.noLive = opts.NoLive
	app.openCategory(opts.StartCategory)
	_, err := tea.NewProgram(app, tea.WithContext(ctx)).Run()
	// A signal (SIGINT/SIGTERM) that cancels ctx is a clean shutdown, not an error.
	if errors.Is(err, tea.ErrProgramKilled) || errors.Is(err, tea.ErrInterrupted) {
		return nil
	}
	return err
}
