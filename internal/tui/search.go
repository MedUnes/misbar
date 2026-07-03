package tui

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
)

// searchState tracks an in-content search over the full-screen view.
type searchState struct {
	inputting bool // the query is being typed
	query     string
	matches   []int
	idx       int
}

// active reports whether a search is being typed or has committed matches.
func (s searchState) active() bool {
	return s.inputting || s.query != ""
}

// handleSearchInput consumes a key while the search query is being typed.
func (a *App) handleSearchInput(msg tea.KeyPressMsg) {
	switch msg.String() {
	case "enter":
		a.commitSearch()
	case "esc":
		a.clearSearch()
	case "backspace":
		if n := len(a.search.query); n > 0 {
			a.search.query = a.search.query[:n-1]
		}
	default:
		if msg.Text != "" { // a printable character
			a.search.query += msg.Text
		}
	}
}

// commitSearch runs the query against the full-screen content and jumps to the
// first match (or restores the plain view when there are none).
func (a *App) commitSearch() {
	a.search.inputting = false
	a.search.matches = a.full.find(a.search.query)
	a.search.idx = 0
	if len(a.search.matches) > 0 {
		a.full.highlight(a.search.matches, a.search.idx)
	} else {
		a.full.restore()
	}
}

// clearSearch drops the search and restores the styled content.
func (a *App) clearSearch() {
	a.search = searchState{}
	if a.full.ready {
		a.full.restore()
	}
}

// searchStatus is the bottom-bar text while searching in the full-screen view.
func (a *App) searchStatus() string {
	switch {
	case a.search.inputting:
		return "/" + a.search.query + "▌  enter search · esc cancel"
	case len(a.search.matches) == 0:
		return "/" + a.search.query + "  — no matches · esc clear"
	default:
		return fmt.Sprintf("/%s  %d/%d · n next · N prev · esc clear",
			a.search.query, a.search.idx+1, len(a.search.matches))
	}
}

// cycleMatch moves to the next (delta=+1) or previous (delta=-1) match.
func (a *App) cycleMatch(delta int) {
	if len(a.search.matches) == 0 {
		return
	}
	n := len(a.search.matches)
	a.search.idx = (a.search.idx + delta + n) % n
	a.full.highlight(a.search.matches, a.search.idx)
}
