package tui

import (
	"fmt"

	"charm.land/lipgloss/v2"
)

const (
	gridCols = 3
	gridRows = 2
)

// overviewModel renders the landing dashboard: a 3×2 grid of category panels
// showing health badge + aggregate summary. It is a plain renderer; App owns
// the state and injects it before calling View.
type overviewModel struct {
	styles *Styles
	cats   []*categoryState
	focus  int // 0..5, the highlighted panel
}

// View renders the grid filling exactly w×h; widths/heights are distributed so
// panels sum to the full area with no overflow or gap.
func (o overviewModel) View(w, h int) string {
	colWidths := distribute(w, gridCols)
	rowHeights := distribute(h, gridRows)

	rows := make([]string, 0, gridRows)
	for r := range gridRows {
		cells := make([]string, 0, gridCols)
		for c := range gridCols {
			cells = append(cells, o.renderPanel(r*gridCols+c, colWidths[c], rowHeights[r]))
		}
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, cells...))
	}
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

// renderPanel draws one bordered category panel of exactly pw×ph.
func (o overviewModel) renderPanel(idx, pw, ph int) string {
	focused := idx == o.focus
	titleStyle := o.styles.PanelTitle
	if focused {
		titleStyle = o.styles.PanelTitleFocused
	}

	lines := []string{titleStyle.Render("—"), "", o.styles.Dim.Render("scanning…")}
	if idx < len(o.cats) {
		c := o.cats[idx]
		h := c.health()
		title := titleStyle.Render(fmt.Sprintf("%d  %s", c.meta.ID, c.meta.Label))
		status := c.health().Badge() + " " + o.styles.healthStyle(h).Render(c.Summary())
		lines = []string{title, "", status}
		if a := c.topAnomaly(); a != nil {
			lines = append(lines, o.styles.Dim.Render(a.Title))
		}
	}
	body := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return o.styles.panel(pw, ph, focused, body)
}

// distribute splits total into n parts that sum exactly to total, handing the
// remainder to the leftmost parts. Never returns negative sizes.
func distribute(total, n int) []int {
	if n <= 0 {
		return nil
	}
	if total < 0 {
		total = 0
	}
	base, extra := total/n, total%n
	out := make([]int, n)
	for i := range out {
		out[i] = base
		if i < extra {
			out[i]++
		}
	}
	return out
}
